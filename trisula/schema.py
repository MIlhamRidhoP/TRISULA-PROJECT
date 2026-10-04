import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError
from pydantic.json_schema import GenerateJsonSchema

Confidence = Literal["high", "medium", "low"]
SastAction = Literal["confirmed", "rejected", "added", "none"]
CallStatus = Literal["ok", "invalid_format", "network_error", "api_error"]


class CweVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cwe: str
    vulnerable: bool
    line: int | None
    confidence: Confidence
    reason: str
    recommendation: str | None


class LLMVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdicts: list[CweVerdict]


class Finding(BaseModel):
    case_id: str
    file: str
    cwe: str
    vulnerable: bool | None
    line: int | None = None
    source: str
    scenario: str
    run: int
    sast_action: SastAction | None = None
    confidence: Confidence | None = None
    reason: str | None = None
    recommendation: str | None = None
    error: str | None = None
    fallback: bool = False


class CallLog(BaseModel):
    timestamp: str
    case_id: str
    scenario: str
    model_key: str
    model_id: str
    run: int
    attempt: int
    cache_hit: bool
    input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    cached_tokens: int | None = None
    latency_ms: float | None
    cost_usd: float | None
    status: CallStatus
    error_message: str | None = None
    request_params: dict[str, Any] = {}
    raw_response: str | None = None


class _PlainJsonSchema(GenerateJsonSchema):
    """Skema tanpa title dan dengan nullable sebagai list tipe, sesuai bentuk di DESIGN.md."""

    def field_title_should_be_set(self, schema: Any) -> bool:
        return False

    def nullable_schema(self, schema: Any) -> dict[str, Any]:
        inner = self.generate_inner(schema["schema"])
        return {**inner, "type": [inner["type"], "null"]}


def _inline_refs(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if "$ref" in node:
            return _inline_refs(defs[node["$ref"].rsplit("/", 1)[-1]], defs)
        return {key: _inline_refs(child, defs) for key, child in node.items() if key != "title"}
    if isinstance(node, list):
        return [_inline_refs(child, defs) for child in node]
    return node


def verdict_json_schema(cwe_ids: list[str]) -> dict[str, Any]:
    """Skema respons LLM (DESIGN.md bagian 5) dengan enum CWE dari konfigurasi."""
    generated = LLMVerdict.model_json_schema(schema_generator=_PlainJsonSchema)
    defs = generated.pop("$defs")
    schema = _inline_refs(generated, defs)
    schema["properties"]["verdicts"]["items"]["properties"]["cwe"]["enum"] = list(cwe_ids)
    return schema


class InvalidResponseError(ValueError):
    pass


def parse_llm_response(text: str, cwe_ids: list[str], line_count: int) -> tuple[LLMVerdict, list[str]]:
    """Validasi skema dan aturan tambahan DESIGN.md bagian 5. Mengembalikan putusan dan peringatan."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidResponseError(f"response is not valid JSON: {exc}") from exc
    try:
        parsed = LLMVerdict.model_validate(payload)
    except ValidationError as exc:
        raise InvalidResponseError(f"response does not match schema: {exc.error_count()} errors") from exc

    seen = [verdict.cwe for verdict in parsed.verdicts]
    unknown = sorted(set(seen) - set(cwe_ids))
    duplicated = sorted({cwe for cwe in seen if seen.count(cwe) > 1})
    missing = sorted(set(cwe_ids) - set(seen))
    if unknown or duplicated or missing:
        raise InvalidResponseError(
            f"verdict set mismatch: unknown={unknown} duplicated={duplicated} missing={missing}"
        )

    warnings = []
    for verdict in parsed.verdicts:
        if verdict.line is not None and not 1 <= verdict.line <= line_count:
            warnings.append(f"{verdict.cwe}: line {verdict.line} outside 1..{line_count}, set to null")
            verdict.line = None
        if verdict.vulnerable and not verdict.recommendation:
            warnings.append(f"{verdict.cwe}: vulnerable verdict without recommendation")
    return parsed, warnings
