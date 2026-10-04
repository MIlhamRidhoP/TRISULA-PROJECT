import json
from types import SimpleNamespace

import httpx
import openai
import pytest
from google.genai import errors as genai_errors
from tenacity import wait_none

from trisula.llm.base import CompletionRequest, FatalAPIError, TransientAPIError
from trisula.llm.mock import MockAdapter
from trisula.review import run_review

from .conftest import make_config, prepare_workspace

FAKE_KEY = "sk-trisula-test-7f3a9c1e5b2d4086a1c3e5f7"


def read_call_log(config, scenario: str, model: str, run: int) -> list[dict]:
    path = config.results_dir / "raw" / f"calls-{scenario}-{model}-run{run}.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def fake_openai_response(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        output_text=text,
        status="completed",
        incomplete_details=None,
        usage=SimpleNamespace(
            input_tokens=1000,
            output_tokens=500,
            output_tokens_details=SimpleNamespace(reasoning_tokens=300),
            input_tokens_details=SimpleNamespace(cached_tokens=0),
        ),
    )


def valid_verdicts_json() -> str:
    verdict = {"vulnerable": False, "line": None, "confidence": "low", "reason": "r", "recommendation": None}
    return json.dumps({"verdicts": [{"cwe": "CWE-89", **verdict}, {"cwe": "CWE-79", **verdict}]})


def http_error(error_class, status: int, message: str):
    request = httpx.Request("POST", "https://api.example.test/v1/responses")
    return error_class(message, response=httpx.Response(status, request=request), body=None)


def test_second_review_uses_cache_without_calling_adapter(tmp_path, monkeypatch):
    config = prepare_workspace(tmp_path)
    run_review(config, "mock", "B", [1])

    def fail_if_called(self, request):
        raise AssertionError("adapter called despite cache")

    monkeypatch.setattr(MockAdapter, "complete", fail_if_called)
    outcomes = run_review(config, "mock", "B", [1])[1]
    assert all(outcome.cache_hit for outcome in outcomes)
    assert all(entry["cache_hit"] for entry in read_call_log(config, "B", "mock", 1))


def test_different_runs_are_not_served_from_the_same_cache_entry(tmp_path, monkeypatch):
    config = prepare_workspace(tmp_path)
    run_review(config, "mock", "B", [1])
    outcomes = run_review(config, "mock", "B", [2])[2]
    assert not any(outcome.cache_hit for outcome in outcomes)


def test_broken_responses_are_retried_then_recorded_as_format_error(tmp_path):
    config = prepare_workspace(tmp_path, **{"llm.models.mock.invalid_response_rate": 1.0})
    outcomes = run_review(config, "mock", "C", [1], limit=2)[1]

    assert [o.error for o in outcomes] == ["invalid_format", "invalid_format"]
    assert all(o.verdicts is None and o.attempts == 1 + config.llm.max_format_retries for o in outcomes)
    log = read_call_log(config, "C", "mock", 1)
    assert len(log) == 2 * (1 + config.llm.max_format_retries)
    assert {entry["status"] for entry in log} == {"invalid_format"}


def test_network_errors_are_retried_and_not_cached(tmp_path, monkeypatch):
    config = prepare_workspace(tmp_path)
    calls = []

    def always_unavailable(self, request):
        calls.append(request.attempt)
        raise TransientAPIError("HTTP 503: unavailable")

    monkeypatch.setattr(MockAdapter, "complete", always_unavailable)
    outcomes = run_review(config, "mock", "C", [1], limit=1, wait=wait_none())[1]

    assert outcomes[0].error == "network_error"
    assert len(calls) == 1 + config.llm.max_network_retries
    assert not list((config.cache_dir / "llm").rglob("*.json"))


def test_client_error_stops_review_without_retry(tmp_path, monkeypatch):
    config = prepare_workspace(tmp_path)
    calls = []

    def unauthorized(self, request):
        calls.append(1)
        raise FatalAPIError("mock: HTTP 401: invalid key")

    monkeypatch.setattr(MockAdapter, "complete", unauthorized)
    with pytest.raises(FatalAPIError, match="401"):
        run_review(config, "mock", "C", [1], limit=1, wait=wait_none())
    assert len(calls) == 1


def test_api_key_never_reaches_logs_cache_or_outputs(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    config = prepare_workspace(tmp_path, **{"llm.max_concurrent_requests": 1})
    scripted = [
        http_error(openai.RateLimitError, 429, f"Rate limited for key {FAKE_KEY}"),
        fake_openai_response(f"not json, echoing {FAKE_KEY}"),
    ]

    def create(**kwargs):
        if not scripted:
            return fake_openai_response(valid_verdicts_json())
        reply = scripted.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    fake_client = SimpleNamespace(responses=SimpleNamespace(create=create))
    monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: fake_client)
    outcomes = run_review(config, "gpt", "B", [1], limit=2, wait=wait_none())[1]

    assert outcomes[0].attempts == 3
    assert all(outcome.verdicts is not None for outcome in outcomes)
    leaked = [
        path for path in tmp_path.rglob("*") if path.is_file() and FAKE_KEY in path.read_text(errors="ignore")
    ]
    assert leaked == []
    assert FAKE_KEY not in caplog.text
    log = read_call_log(config, "B", "gpt", 1)
    assert [entry["status"] for entry in log[:3]] == ["network_error", "invalid_format", "ok"]
    assert "[REDACTED]" in log[0]["error_message"]
    assert log[2]["cost_usd"] == pytest.approx((1000 * 1.75 + 500 * 14.0) / 1_000_000)


def test_missing_api_key_names_the_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    config = prepare_workspace(tmp_path)
    with pytest.raises(Exception, match="XAI_API_KEY is not set"):
        run_review(config, "grok", "C", [1], limit=1)


def request_for(schema_cwes=("CWE-89", "CWE-79")) -> CompletionRequest:
    from trisula.schema import verdict_json_schema

    return CompletionRequest("sys", "user", verdict_json_schema(list(schema_cwes)), "a/Case0001.java", 1, 1)


@pytest.mark.parametrize(
    ("status", "expected"),
    [(429, TransientAPIError), (503, TransientAPIError), (400, FatalAPIError), (404, FatalAPIError)],
)
def test_openai_status_codes_map_to_retry_or_stop(tmp_path, monkeypatch, status, expected):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    from trisula.llm.openai_compat import OpenAICompatAdapter

    config = make_config(tmp_path)
    adapter = OpenAICompatAdapter("gpt", config.llm.models["gpt"], config.llm)
    error = http_error(openai.APIStatusError, status, "boom")

    def raise_error(**kwargs):
        raise error

    adapter._client = SimpleNamespace(responses=SimpleNamespace(create=raise_error))
    with pytest.raises(expected):
        adapter.complete(request_for())


@pytest.mark.parametrize(
    ("code", "expected"),
    [(429, TransientAPIError), (500, TransientAPIError), (400, FatalAPIError), (403, FatalAPIError)],
)
def test_gemini_status_codes_map_to_retry_or_stop(tmp_path, monkeypatch, code, expected):
    monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
    from trisula.llm.gemini import GeminiAdapter

    config = make_config(tmp_path)
    adapter = GeminiAdapter("gemini", config.llm.models["gemini"], config.llm)
    error_class = genai_errors.ClientError if code < 500 else genai_errors.ServerError

    def raise_error(**kwargs):
        raise error_class(code, {"error": {"code": code, "message": "boom", "status": "X"}})

    adapter._client = SimpleNamespace(models=SimpleNamespace(generate_content=raise_error))
    with pytest.raises(expected):
        adapter.complete(request_for())


def test_gemini_thought_tokens_are_counted_as_output(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
    from google.genai import types

    from trisula.llm.gemini import GeminiAdapter

    config = make_config(tmp_path)
    adapter = GeminiAdapter("gemini", config.llm.models["gemini"], config.llm)
    response = SimpleNamespace(
        text=valid_verdicts_json(),
        candidates=[SimpleNamespace(finish_reason=types.FinishReason.STOP)],
        usage_metadata=SimpleNamespace(
            prompt_token_count=900,
            candidates_token_count=150,
            thoughts_token_count=600,
            cached_content_token_count=None,
        ),
    )
    adapter._client = SimpleNamespace(models=SimpleNamespace(generate_content=lambda **kwargs: response))
    completion = adapter.complete(request_for())
    assert (completion.input_tokens, completion.output_tokens, completion.reasoning_tokens) == (900, 750, 600)
    assert completion.request_params["thinking_level"] == "MEDIUM"
