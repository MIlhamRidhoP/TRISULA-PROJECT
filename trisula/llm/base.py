import hashlib
import json
import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_exponential
from tenacity.wait import wait_base

from trisula.codeql import CodeQLAlert
from trisula.config import Config, LLMConfig, ModelConfig, TrisulaError
from trisula.llm.prompt import PromptTemplate, RenderedPrompt, build_prompt
from trisula.schema import CallLog, CweVerdict, InvalidResponseError, parse_llm_response, verdict_json_schema

log = logging.getLogger(__name__)

REDACTED = "[REDACTED]"


class TransientAPIError(Exception):
    """Kegagalan jaringan, HTTP 429, atau 5xx. Diulang dengan backoff (DESIGN.md bagian 7)."""


class FatalAPIError(TrisulaError):
    """Error 4xx selain 429: masalah konfigurasi, tidak diulang dan menghentikan proses."""


@dataclass(frozen=True)
class CompletionRequest:
    system: str
    user: str
    schema: dict[str, Any]
    # Tiga field di bawah hanya dipakai adaptor mock supaya putusannya deterministik.
    file_path: str
    run: int
    attempt: int


@dataclass
class Completion:
    text: str
    input_tokens: int | None
    output_tokens: int | None  # termasuk token reasoning
    reasoning_tokens: int | None
    cached_tokens: int | None = None
    truncated: bool = False
    request_params: dict[str, Any] = field(default_factory=dict)


class LLMAdapter(ABC):
    def __init__(self, model_key: str, model: ModelConfig, llm: LLMConfig):
        self.model_key = model_key
        self.model = model
        self.llm = llm
        self.api_key = self._read_api_key()

    def _read_api_key(self) -> str | None:
        if self.model.api_key_env is None:
            return None
        api_key = os.environ.get(self.model.api_key_env)
        if not api_key:
            raise TrisulaError(f"environment variable {self.model.api_key_env} is not set")
        return api_key

    @abstractmethod
    def complete(self, request: CompletionRequest) -> Completion: ...

    def redact(self, text: str | None) -> str | None:
        if text is None or not self.api_key:
            return text
        return text.replace(self.api_key, REDACTED)


class CaseOutcome(BaseModel):
    case_id: str
    file: str
    scenario: str
    model_key: str
    model_id: str
    run: int
    verdicts: list[CweVerdict] | None
    error: str | None = None
    error_message: str | None = None
    warnings: list[str] = []
    attempts: int
    cache_hit: bool
    cost_usd: float | None
    latency_ms: float
    input_tokens: int | None
    output_tokens: int | None


@dataclass
class AttemptRecord:
    status: str
    text: str | None
    input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    cached_tokens: int | None
    latency_ms: float
    cost_usd: float | None
    request_params: dict[str, Any]
    error_message: str | None = None


@dataclass(frozen=True)
class ReviewCase:
    file: str
    code: str
    alerts: list[CodeQLAlert]

    @property
    def case_id(self) -> str:
        return Path(self.file).stem


class CallLogWriter:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = path.open("w", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, entry: CallLog) -> None:
        with self._lock:
            self._handle.write(entry.model_dump_json() + "\n")
            self._handle.flush()

    def close(self) -> None:
        self._handle.close()


def compute_cost(model: ModelConfig, input_tokens: int | None, output_tokens: int | None) -> float | None:
    if input_tokens is None or output_tokens is None:
        return None
    return (
        input_tokens * model.price_input_per_mtok + output_tokens * model.price_output_per_mtok
    ) / 1_000_000


class Reviewer:
    """Satu jalur pemanggilan LLM per file: render prompt, cache, retry, validasi, biaya, dan log."""

    def __init__(
        self,
        config: Config,
        scenario: str,
        adapter: LLMAdapter,
        template: PromptTemplate,
        call_log: CallLogWriter,
        wait: wait_base | None = None,
    ):
        self.config = config
        self.scenario = scenario
        self.adapter = adapter
        self.template = template
        self.call_log = call_log
        self.wait = wait or wait_exponential(multiplier=2, max=60)
        self.schema = verdict_json_schema(config.cwe_ids)
        self.cache_dir = config.cache_dir / "llm" / adapter.model_key

    @property
    def scenario_name(self) -> str:
        return f"{self.scenario}-{self.adapter.model_key}"

    def cache_key(self, prompt: RenderedPrompt, run: int) -> str:
        payload = {
            "model_id": self.adapter.model.model_id,
            "prompt_version": self.template.version,
            "system": prompt.system,
            "user": prompt.user,
            "run": run,
            "reasoning": self.adapter.model.reasoning,
            "max_output_tokens": self.config.llm.max_output_tokens,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def review(self, case: ReviewCase, run: int) -> CaseOutcome:
        prompt = build_prompt(self.template, self.config, self.scenario, case.file, case.code, case.alerts)
        key = self.cache_key(prompt, run)
        cache_path = self.cache_dir / f"{key}.json"
        cache_hit = cache_path.exists()
        if cache_hit:
            records = [AttemptRecord(**entry) for entry in json.loads(cache_path.read_text(encoding="utf-8"))]
        else:
            records = self._call_until_valid(case, prompt, run)
            # Kegagalan jaringan bersifat sementara; yang di-cache hanya respons dari API.
            if records[-1].status != "network_error":
                self._write_cache(cache_path, [r for r in records if r.status != "network_error"])

        line_count = len(case.code.splitlines())
        for number, record in enumerate(records, start=1):
            self._log_attempt(case, run, number, record, cache_hit)
        return self._outcome(case, run, records, line_count, cache_hit)

    def _call_until_valid(self, case: ReviewCase, prompt: RenderedPrompt, run: int) -> list[AttemptRecord]:
        records: list[AttemptRecord] = []
        line_count = len(case.code.splitlines())
        for _ in range(1 + self.config.llm.max_format_retries):
            try:
                completion, latency_ms = self._call_with_network_retry(case, prompt, run, records)
            except TransientAPIError:
                return records
            status, error_message = "ok", None
            if completion.truncated:
                status, error_message = "invalid_format", "response truncated at max_output_tokens"
            else:
                try:
                    parse_llm_response(completion.text, self.config.cwe_ids, line_count)
                except InvalidResponseError as exc:
                    status, error_message = "invalid_format", str(exc)
            records.append(
                AttemptRecord(
                    status=status,
                    text=self.adapter.redact(completion.text),
                    input_tokens=completion.input_tokens,
                    output_tokens=completion.output_tokens,
                    reasoning_tokens=completion.reasoning_tokens,
                    cached_tokens=completion.cached_tokens,
                    latency_ms=latency_ms,
                    cost_usd=compute_cost(
                        self.adapter.model, completion.input_tokens, completion.output_tokens
                    ),
                    request_params=completion.request_params,
                    error_message=error_message,
                )
            )
            if status == "ok":
                break
        return records

    def _call_with_network_retry(
        self, case: ReviewCase, prompt: RenderedPrompt, run: int, records: list[AttemptRecord]
    ) -> tuple[Completion, float]:
        retrying = Retrying(
            retry=retry_if_exception_type(TransientAPIError),
            stop=stop_after_attempt(1 + self.config.llm.max_network_retries),
            wait=self.wait,
            reraise=True,
        )
        return retrying(self._call_once, case, prompt, run, records)

    def _call_once(
        self, case: ReviewCase, prompt: RenderedPrompt, run: int, records: list[AttemptRecord]
    ) -> tuple[Completion, float]:
        request = CompletionRequest(
            system=prompt.system,
            user=prompt.user,
            schema=self.schema,
            file_path=case.file,
            run=run,
            attempt=len(records) + 1,
        )
        started = time.perf_counter()
        try:
            completion = self.adapter.complete(request)
        except TransientAPIError as exc:
            records.append(self._failed_record("network_error", exc, started))
            raise
        except FatalAPIError as exc:
            self._log_attempt(
                case, run, len(records) + 1, self._failed_record("api_error", exc, started), False
            )
            raise FatalAPIError(self.adapter.redact(str(exc))) from None
        return completion, (time.perf_counter() - started) * 1000

    def _failed_record(self, status: str, exc: Exception, started: float) -> AttemptRecord:
        return AttemptRecord(
            status=status,
            text=None,
            input_tokens=None,
            output_tokens=None,
            reasoning_tokens=None,
            cached_tokens=None,
            latency_ms=(time.perf_counter() - started) * 1000,
            cost_usd=None,
            request_params={},
            error_message=self.adapter.redact(f"{type(exc).__name__}: {exc}"),
        )

    def _write_cache(self, path: Path, records: list[AttemptRecord]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps([asdict(record) for record in records], indent=1), encoding="utf-8")
        temporary.replace(path)

    def _log_attempt(
        self, case: ReviewCase, run: int, number: int, record: AttemptRecord, cache_hit: bool
    ) -> None:
        self.call_log.write(
            CallLog(
                timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
                case_id=case.case_id,
                scenario=self.scenario_name,
                model_key=self.adapter.model_key,
                model_id=self.adapter.model.model_id,
                run=run,
                attempt=number,
                cache_hit=cache_hit,
                input_tokens=record.input_tokens,
                output_tokens=record.output_tokens,
                reasoning_tokens=record.reasoning_tokens,
                cached_tokens=record.cached_tokens,
                latency_ms=record.latency_ms,
                cost_usd=record.cost_usd,
                status=record.status,
                error_message=record.error_message,
                request_params=record.request_params,
                raw_response=record.text,
            )
        )

    def _outcome(
        self, case: ReviewCase, run: int, records: list[AttemptRecord], line_count: int, cache_hit: bool
    ) -> CaseOutcome:
        final = records[-1]
        verdicts, warnings = None, []
        if final.status == "ok":
            parsed, warnings = parse_llm_response(final.text, self.config.cwe_ids, line_count)
            verdicts = parsed.verdicts
            for warning in warnings:
                log.warning("%s run %d: %s", case.case_id, run, warning)
        costs = [r.cost_usd for r in records if r.cost_usd is not None]
        return CaseOutcome(
            case_id=case.case_id,
            file=case.file,
            scenario=self.scenario_name,
            model_key=self.adapter.model_key,
            model_id=self.adapter.model.model_id,
            run=run,
            verdicts=verdicts,
            error=None if final.status == "ok" else final.status,
            error_message=final.error_message,
            warnings=warnings,
            attempts=len(records),
            cache_hit=cache_hit,
            cost_usd=sum(costs) if costs else None,
            latency_ms=sum(r.latency_ms for r in records),
            input_tokens=sum(r.input_tokens or 0 for r in records),
            output_tokens=sum(r.output_tokens or 0 for r in records),
        )
