import json

import pytest

from trisula.codeql import codeql_findings, normalize_cwe_tag, parse_sarif, run_parse_sarif

from .conftest import DEMO_SARIF, DEMO_TIMING

CWE_IDS = ["CWE-89", "CWE-79"]
CASES = "targets/benchmark/src/main/java/com/example/webapp/cases/"


@pytest.fixture
def sarif() -> dict:
    return json.loads(DEMO_SARIF.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("external/cwe/cwe-089", "CWE-89"),
        ("external/cwe/cwe-079", "CWE-79"),
        ("external/cwe/cwe-1004", "CWE-1004"),
        ("security", None),
        ("external/owasp/owasp-a03", None),
    ],
)
def test_cwe_tags_are_normalized(tag, expected):
    assert normalize_cwe_tag(tag) == expected


def test_out_of_scope_rule_is_ignored(sarif):
    alerts = parse_sarif(sarif, CWE_IDS)
    assert len(alerts) == 7
    assert "java/stack-trace-exposure" not in {alert.rule_id for alert in alerts}


def test_alerts_resolve_rules_from_extensions(sarif):
    alerts = parse_sarif(sarif, CWE_IDS)
    sqli = [a for a in alerts if a.rule_id == "java/sql-injection"]
    assert len(sqli) == 3
    assert all(a.cwes == ["CWE-89"] for a in sqli)
    assert {a.cwes[0] for a in alerts if a.rule_id == "java/xss"} == {"CWE-79"}


def test_code_flow_is_rendered_as_steps(sarif):
    alert = next(a for a in parse_sarif(sarif, CWE_IDS) if a.file.endswith("Case0006.java"))
    assert alert.line == 33
    assert alert.flow == [
        "line 26: getParameter(...) : String",
        "line 30: ... + ... : String",
        "line 33: sql",
    ]


def test_rule_found_by_index_when_result_has_no_rule_id(sarif):
    result = sarif["runs"][0]["results"][3]
    del result["ruleId"], result["rule"]["id"]
    alerts = parse_sarif(sarif, CWE_IDS)
    assert alerts[3].rule_id == "java/xss"


def test_note_level_alert_still_counts(sarif):
    sarif["runs"][0]["results"][0]["level"] = "note"
    alerts = parse_sarif(sarif, CWE_IDS)
    assert alerts[0].level == "note"
    findings = codeql_findings(alerts, [CASES + "Case0008.java"], CWE_IDS)
    assert findings[0].vulnerable is True


def test_findings_only_count_alerts_with_matching_cwe(sarif):
    alerts = parse_sarif(sarif, CWE_IDS)
    files = [CASES + "Case0008.java", CASES + "Case0003.java"]
    findings = {(f.case_id, f.cwe): f for f in codeql_findings(alerts, files, CWE_IDS)}
    assert findings[("Case0008", "CWE-89")].vulnerable is True
    assert findings[("Case0008", "CWE-89")].line == 41
    assert findings[("Case0008", "CWE-79")].vulnerable is False
    assert findings[("Case0003", "CWE-89")].vulnerable is False
    assert all(f.source == "codeql" and f.scenario == "A" for f in findings.values())


def test_parse_sarif_command_records_duration(mini_config):
    results = run_parse_sarif(mini_config, [DEMO_SARIF], DEMO_TIMING)
    assert results.duration_seconds == 84.0
    assert (mini_config.results_dir / "codeql/alerts.json").exists()
