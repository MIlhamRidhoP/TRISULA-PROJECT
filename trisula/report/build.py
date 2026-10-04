import json
import logging
import os
from pathlib import Path

import matplotlib.pyplot as plt

from trisula import __version__
from trisula.config import Config, TrisulaError
from trisula.ensemble import load_findings
from trisula.report import developer_findings
from trisula.report.figures import build_figures, figure_svg, save_figures
from trisula.report.html import render_html
from trisula.report.pr_comment import render_pr_comment
from trisula.report.sarif import model_sarif

log = logging.getLogger(__name__)


def _workflow_run_url() -> str | None:
    server, repository, run_id = (
        os.environ.get(k) for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID")
    )
    return f"{server}/{repository}/actions/runs/{run_id}" if server and repository and run_id else None


def run_report(config: Config) -> list[Path]:
    summary_path = config.results_dir / "summary.json"
    if not summary_path.exists():
        raise TrisulaError(f"{summary_path} not found; run `evaluate` first")
    report = json.loads(summary_path.read_text(encoding="utf-8"))
    findings = load_findings(config)
    primary_run = config.llm.primary_run
    grouped = developer_findings(findings, primary_run)
    written: list[Path] = []

    if config.report.sarif:
        sarif_dir = config.results_dir / "sarif"
        sarif_dir.mkdir(parents=True, exist_ok=True)
        models = sorted({f.source for f in findings if f.scenario.startswith("B-") and f.run == primary_run})
        for model_key in models:
            model_findings = [f for f in findings if f.scenario == f"B-{model_key}" and f.run == primary_run]
            sarif = model_sarif(
                model_findings, model_key, config.llm.models[model_key].model_id, config, __version__
            )
            path = sarif_dir / f"trisula-{model_key}.sarif"
            path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
            written.append(path)

    if config.report.pr_comment:
        path = config.results_dir / "pr_comment.md"
        path.write_text(
            render_pr_comment(grouped, config.report.max_pr_findings, _workflow_run_url()), encoding="utf-8"
        )
        written.append(path)

    figures = build_figures(report, config)
    written += save_figures(figures, config.results_dir / "figures", config.report.figures.format)
    if config.report.html:
        path = config.results_dir / "report.html"
        svgs = {name: figure_svg(figure) for name, figure in figures.items()}
        case_count = report["scenarios"]["A"]["errors"]["cases"]
        path.write_text(render_html(report, grouped, svgs, config, case_count), encoding="utf-8")
        written.append(path)
    for figure in figures.values():
        plt.close(figure)

    log.info(
        "wrote %d report files (%d findings for developers) -> %s",
        len(written),
        len(grouped),
        config.results_dir,
    )
    return written
