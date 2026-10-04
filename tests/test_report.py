import json

import jsonschema
import pytest

from trisula.ensemble import run_ensemble
from trisula.evaluate import evaluate
from trisula.report import developer_findings
from trisula.report.build import run_report
from trisula.report.pr_comment import render_pr_comment
from trisula.review import run_review
from trisula.schema import Finding

from .conftest import FIXTURES, MOCK_MEMBERS, mock_ensemble_overrides, prepare_workspace


def sarif_validator() -> jsonschema.Draft4Validator:
    schema = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    return jsonschema.Draft4Validator(schema)


@pytest.fixture(scope="module")
def reported(tmp_path_factory):
    root = tmp_path_factory.mktemp("report")
    config = prepare_workspace(root, **mock_ensemble_overrides())
    for model in MOCK_MEMBERS:
        run_review(config, model, "B", [1, 2, 3])
        run_review(config, model, "C", [1])
    run_ensemble(config)
    evaluate(config)
    return config, run_report(config)


def test_exported_sarif_is_valid_against_sarif_schema(reported):
    config, _ = reported
    validator = sarif_validator()
    paths = sorted((config.results_dir / "sarif").glob("*.sarif"))
    assert [p.name for p in paths] == [f"trisula-{m}.sarif" for m in MOCK_MEMBERS]
    for path in paths:
        sarif = json.loads(path.read_text(encoding="utf-8"))
        validator.validate(sarif)
        assert sarif["runs"][0]["tool"]["driver"]["name"] == path.stem
        assert all(r["ruleId"] in {"CWE-89", "CWE-79"} for r in sarif["runs"][0]["results"])


def test_codeql_fixture_is_valid_sarif():
    sarif_validator().validate(json.loads((FIXTURES / "codeql/demo.sarif").read_text(encoding="utf-8")))


def test_html_report_has_both_sections_and_inline_figures(reported):
    config, _ = reported
    html = (config.results_dir / "report.html").read_text(encoding="utf-8")
    assert "<h2>Evaluation</h2>" in html and "<h2>Developer view</h2>" in html
    assert html.count("<svg") == 4
    assert 'id="filter-cwe"' in html and 'id="filter-source"' in html
    assert "McNemar" in html


def test_paper_figures_are_written_as_pdf(reported):
    config, _ = reported
    figures = sorted(p.name for p in (config.results_dir / "figures").iterdir())
    assert figures == [
        "fig1_tpr_fpr_by_cwe.pdf",
        "fig2_roc_space.pdf",
        "fig3_sast_action.pdf",
        "fig4_cost_vs_score.pdf",
    ]
    assert all((config.results_dir / "figures" / name).read_bytes().startswith(b"%PDF") for name in figures)


def finding(
    scenario: str, source: str, case: str, vulnerable: bool, confidence=None, fallback=False
) -> Finding:
    return Finding(
        case_id=case,
        file=f"cases/{case}.java",
        cwe="CWE-89",
        vulnerable=vulnerable,
        line=10,
        source=source,
        scenario=scenario,
        run=1,
        confidence=confidence,
        reason=f"{source} says so",
        recommendation="Use a PreparedStatement." if source != "codeql" else None,
        fallback=fallback,
    )


def test_developer_findings_rank_by_agreement_then_confidence_and_skip_fallback():
    findings = [
        finding("A", "codeql", "Case0001", True),
        finding("B-gpt", "gpt", "Case0001", True, "low"),
        finding("B-grok", "grok", "Case0002", True, "high"),
        finding("B-gemini", "gemini", "Case0003", True, "low"),
        finding("B-gpt", "gpt", "Case0003", True, fallback=True),
        finding("B-gemini", "gemini", "Case0004", False, "high"),
    ]
    grouped = developer_findings(findings, primary_run=1)
    assert [(g.case_id, g.sources) for g in grouped] == [
        ("Case0001", ["codeql", "gpt"]),
        ("Case0002", ["grok"]),
        ("Case0003", ["gemini"]),
    ]


def test_pr_comment_is_capped_and_links_report():
    findings = [finding("B-gpt", "gpt", f"Case{n:04d}", True, "high") for n in range(1, 6)]
    comment = render_pr_comment(
        developer_findings(findings, 1), max_findings=2, report_url="https://ci/run/1"
    )
    assert comment.count("### ") == 2
    assert "Top 2 of 5 findings" in comment
    assert "| gpt | 5 |" in comment
    assert "- Fix: Use a PreparedStatement." in comment
    assert comment.rstrip().endswith("Full report: https://ci/run/1")


def test_pr_comment_without_findings_says_so():
    comment = render_pr_comment([], max_findings=10, report_url=None)
    assert "No SQL injection or XSS findings" in comment
