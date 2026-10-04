import pytest

from trisula.ensemble import ensemble_findings
from trisula.llm.base import CaseOutcome
from trisula.normalize import llm_findings, sast_action
from trisula.schema import CweVerdict, Finding

CWE_IDS = ["CWE-89", "CWE-79"]
FILE = "cases/Case0001.java"


def codeql_finding(cwe: str, detected: bool, case_id: str = "Case0001") -> Finding:
    return Finding(
        case_id=case_id,
        file=f"cases/{case_id}.java",
        cwe=cwe,
        vulnerable=detected,
        line=12 if detected else None,
        source="codeql",
        scenario="A",
        run=1,
    )


def outcome(scenario: str, vulnerable: dict[str, bool] | None, error: str | None = None) -> CaseOutcome:
    verdicts = None
    if vulnerable is not None:
        verdicts = [
            CweVerdict(cwe=cwe, vulnerable=v, line=None, confidence="high", reason="r", recommendation=None)
            for cwe, v in vulnerable.items()
        ]
    return CaseOutcome(
        case_id="Case0001",
        file=FILE,
        scenario=scenario,
        model_key=scenario.split("-", 1)[1],
        model_id="m",
        run=1,
        verdicts=verdicts,
        error=error,
        attempts=1,
        cache_hit=False,
        cost_usd=0.0,
        latency_ms=1.0,
        input_tokens=1,
        output_tokens=1,
    )


@pytest.mark.parametrize(
    ("codeql_detected", "llm_vulnerable", "expected"),
    [(True, True, "confirmed"), (True, False, "rejected"), (False, True, "added"), (False, False, "none")],
)
def test_sast_action_table(codeql_detected, llm_vulnerable, expected):
    assert sast_action(codeql_detected, llm_vulnerable) == expected


def test_scenario_b_findings_carry_sast_action_per_cwe():
    codeql = {
        (FILE, "CWE-89"): codeql_finding("CWE-89", True),
        (FILE, "CWE-79"): codeql_finding("CWE-79", False),
    }
    findings = llm_findings([outcome("B-gpt", {"CWE-89": False, "CWE-79": True})], codeql, CWE_IDS)
    assert [(f.cwe, f.vulnerable, f.sast_action) for f in findings] == [
        ("CWE-89", False, "rejected"),
        ("CWE-79", True, "added"),
    ]
    assert all(f.source == "gpt" and not f.fallback for f in findings)


def test_scenario_b_error_falls_back_to_codeql():
    codeql = {
        (FILE, "CWE-89"): codeql_finding("CWE-89", True),
        (FILE, "CWE-79"): codeql_finding("CWE-79", False),
    }
    findings = llm_findings([outcome("B-gemini", None, error="invalid_format")], codeql, CWE_IDS)
    assert [(f.vulnerable, f.fallback, f.error, f.sast_action) for f in findings] == [
        (True, True, "invalid_format", None),
        (False, True, "invalid_format", None),
    ]
    assert findings[0].line == 12


def test_scenario_c_error_has_no_verdict_and_no_fallback():
    codeql = {
        (FILE, "CWE-89"): codeql_finding("CWE-89", True),
        (FILE, "CWE-79"): codeql_finding("CWE-79", False),
    }
    findings = llm_findings([outcome("C-gemini", None, error="network_error")], codeql, CWE_IDS)
    assert all(f.vulnerable is None and not f.fallback and f.sast_action is None for f in findings)


def member_finding(model: str, vulnerable: bool | None, error: str | None = None) -> Finding:
    return Finding(
        case_id="Case0001",
        file=FILE,
        cwe="CWE-89",
        vulnerable=vulnerable,
        source=model,
        scenario=f"B-{model}",
        run=1,
        error=error,
        fallback=error is not None,
    )


def vote(*members: Finding, codeql_detected: bool = False) -> Finding:
    findings = [codeql_finding("CWE-89", codeql_detected), *members]
    (ens,) = ensemble_findings(findings, ["gemini", "gpt", "grok"], run=1, min_votes=2)
    return ens


def test_two_of_three_votes_make_case_vulnerable():
    ens = vote(member_finding("gemini", True), member_finding("gpt", True), member_finding("grok", False))
    assert (ens.vulnerable, ens.fallback, ens.scenario) == (True, False, "ENS")


def test_one_of_three_votes_is_not_enough():
    ens = vote(
        member_finding("gemini", True),
        member_finding("gpt", False),
        member_finding("grok", False),
        codeql_detected=True,
    )
    assert (ens.vulnerable, ens.fallback) == (False, False)


def test_errored_member_does_not_vote():
    # gpt error jatuh ke CodeQL (rentan) di Skenario B, tapi suara fallback itu tidak boleh dihitung.
    ens = vote(
        member_finding("gemini", True),
        member_finding("gpt", True, error="invalid_format"),
        member_finding("grok", False),
    )
    assert (ens.vulnerable, ens.fallback) == (False, False)
    assert ens.reason.startswith("1 of 2")


def test_too_few_valid_votes_fall_back_to_codeql():
    ens = vote(
        member_finding("gemini", False),
        member_finding("gpt", None, error="network_error"),
        member_finding("grok", None, error="invalid_format"),
        codeql_detected=True,
    )
    assert (ens.vulnerable, ens.fallback) == (True, True)


def test_other_runs_are_ignored():
    other_run = member_finding("gpt", True).model_copy(update={"run": 2})
    ens = vote(member_finding("gemini", True), other_run, member_finding("grok", False))
    assert ens.vulnerable is False
