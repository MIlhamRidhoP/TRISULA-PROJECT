import json
import re
from pathlib import Path

import pytest

from trisula.schema import InvalidResponseError, parse_llm_response, verdict_json_schema

CWE_IDS = ["CWE-89", "CWE-79"]


def design_doc_schema() -> dict:
    text = Path("docs/DESIGN.md").read_text(encoding="utf-8")
    section = text.split("## 5. Skema respons LLM", 1)[1]
    block = re.search(r"```json\n(.*?)```", section, re.DOTALL).group(1)
    return json.loads(block)


def verdict(cwe: str, vulnerable: bool, line: int | None = 10, recommendation: str | None = "fix") -> dict:
    return {
        "cwe": cwe,
        "vulnerable": vulnerable,
        "line": line,
        "confidence": "high",
        "reason": "r",
        "recommendation": recommendation,
    }


def test_generated_schema_matches_design_doc():
    assert verdict_json_schema(CWE_IDS) == design_doc_schema()


def test_valid_response_parses():
    text = json.dumps({"verdicts": [verdict("CWE-89", True), verdict("CWE-79", False, None, None)]})
    parsed, warnings = parse_llm_response(text, CWE_IDS, line_count=40)
    assert [v.vulnerable for v in parsed.verdicts] == [True, False]
    assert warnings == []


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        json.dumps({"verdicts": [verdict("CWE-89", True)]}),
        json.dumps(
            {"verdicts": [verdict("CWE-89", True), verdict("CWE-89", False), verdict("CWE-79", False)]}
        ),
        json.dumps({"verdicts": [verdict("CWE-89", True), verdict("CWE-22", False)]}),
        json.dumps({"verdicts": [{**verdict("CWE-89", True), "extra": 1}, verdict("CWE-79", False)]}),
    ],
    ids=["not-json", "missing-cwe", "duplicate-cwe", "unknown-cwe", "extra-field"],
)
def test_invalid_responses_are_rejected(payload):
    with pytest.raises(InvalidResponseError):
        parse_llm_response(payload, CWE_IDS, line_count=40)


def test_out_of_range_line_becomes_null_with_warning():
    text = json.dumps({"verdicts": [verdict("CWE-89", True, line=99), verdict("CWE-79", False, None, None)]})
    parsed, warnings = parse_llm_response(text, CWE_IDS, line_count=40)
    assert parsed.verdicts[0].line is None
    assert parsed.verdicts[0].vulnerable is True
    assert "outside 1..40" in warnings[0]


def test_vulnerable_without_recommendation_only_warns():
    text = json.dumps({"verdicts": [verdict("CWE-89", True, recommendation=None), verdict("CWE-79", False)]})
    parsed, warnings = parse_llm_response(text, CWE_IDS, line_count=40)
    assert parsed.verdicts[0].vulnerable is True
    assert warnings == ["CWE-89: vulnerable verdict without recommendation"]
