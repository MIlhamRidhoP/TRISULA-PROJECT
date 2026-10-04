from datetime import UTC, datetime
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from trisula.config import Config
from trisula.report import DeveloperFinding
from trisula.report.figures import ACTIONS

CAPTIONS = {
    "fig1_tpr_fpr_by_cwe": "TPR (solid) and FPR (hatched) per scenario, per CWE.",
    "fig2_roc_space": "Scenarios in TPR vs FPR space, pooled. The dashed diagonal is random guessing.",
    "fig3_sast_action": "What each model did with CodeQL findings. Hatched segments are wrong decisions.",
    "fig4_cost_vs_score": "LLM cost per test case against pooled Benchmark Score.",
}


def fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def sast_action_rows(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    rows, sentences = [], []
    for scenario, entry in report["scenarios"].items():
        breakdown = entry.get("sast_action")
        if not breakdown:
            continue
        for action in ACTIONS:
            counts = breakdown.get(action, {"vulnerable": 0, "not_vulnerable": 0})
            correct_key = "not_vulnerable" if action == "rejected" else "vulnerable"
            wrong_key = "vulnerable" if action == "rejected" else "not_vulnerable"
            rows.append(
                {
                    "scenario": scenario,
                    "action": action,
                    "correct": counts[correct_key],
                    "wrong": counts[wrong_key],
                }
            )
        rejected = breakdown.get("rejected", {"vulnerable": 0, "not_vulnerable": 0})
        right, wrong = rejected["not_vulnerable"], rejected["vulnerable"]
        sentences.append(
            f"{scenario} rejected {right + wrong} CodeQL findings: {right} correctly (not vulnerable), "
            f"{wrong} wrongly (actually vulnerable)."
        )
    return rows, sentences


def consistency_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for scenario, entry in report["scenarios"].items():
        if "consistency" not in entry:
            continue
        score = entry["across_runs"]["pooled"]["benchmark_score"]
        majority = entry.get("majority_of_runs", {}).get("pooled", {})
        rows.append(
            {
                "scenario": scenario,
                "runs": len(entry["consistency"]["runs"]),
                "flip_rate": entry["consistency"]["flip_rate"],
                "agreement": entry["consistency"]["pairwise_agreement"],
                "score_mean": score["mean"],
                "score_sd": score["sd"],
                "majority_score": majority.get("benchmark_score"),
            }
        )
    return rows


def cost_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for scenario, entry in report["scenarios"].items():
        cost = entry.get("time_cost", {}).get(f"run{entry['run']}")
        if cost:
            rows.append({"scenario": scenario, **cost})
    return rows


def render_html(
    report: dict[str, Any],
    findings: list[DeveloperFinding],
    figure_svgs: dict[str, str],
    config: Config,
    case_count: int,
) -> str:
    environment = Environment(
        loader=PackageLoader("trisula.report", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    sast_rows, sast_sentences = sast_action_rows(report)
    return environment.get_template("report.html.j2").render(
        report=report,
        findings=findings,
        figures=figure_svgs,
        captions=CAPTIONS,
        cwe_ids=config.cwe_ids,
        sources=sorted({source for finding in findings for source in finding.sources}),
        sast_rows=sast_rows,
        sast_sentences=sast_sentences,
        consistency_rows=consistency_rows(report),
        cost_rows=cost_rows(report),
        alpha=config.evaluation.alpha,
        case_count=case_count,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        fmt=fmt,
    )
