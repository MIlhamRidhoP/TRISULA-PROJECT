import io
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from trisula.config import Config

# Grafik harus tetap terbaca saat dicetak hitam putih (DESIGN.md bagian 10), jadi pembeda seri
# memakai tingkat abu-abu dan arsiran, bukan warna.
DARK, MID, LIGHT = "#252525", "#7f7f7f", "#d0d0d0"
MARKERS = {"A": "s", "B": "o", "C": "^", "ENS": "D"}
ACTIONS = ("confirmed", "rejected", "added")
ACTION_SHADES = {"confirmed": DARK, "rejected": MID, "added": LIGHT}


def _style(config: Config) -> dict[str, Any]:
    return {
        "font.family": "serif",
        "font.size": config.report.figures.font_size,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.linewidth": 0.6,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "legend.frameon": False,
        "hatch.linewidth": 0.5,
    }


def _short_name(scenario: str) -> str:
    return scenario.replace("B-", "B:").replace("C-", "C:")


def _plot_labeled_points(axis: Any, points: list[tuple[str, float, float]]) -> None:
    # Skenario dengan koordinat sama digabung dalam satu label supaya teksnya tidak bertumpuk.
    grouped: dict[tuple[float, float], list[str]] = {}
    for scenario, x, y in points:
        grouped.setdefault((round(x, 6), round(y, 6)), []).append(scenario)
    # Label titik yang berdekatan diselang-seling di atas dan di bawah titik.
    for position, ((x, y), scenarios) in enumerate(
        sorted(grouped.items(), key=lambda item: (item[0][1], item[0][0]))
    ):
        for scenario in scenarios:
            marker = MARKERS.get(scenario.split("-", 1)[0], "o")
            axis.plot(x, y, marker=marker, markersize=5, color=DARK, linestyle="none", clip_on=False)
        label = ", ".join(_short_name(s) for s in scenarios)
        offset = (5, 4) if position % 2 == 0 else (5, -10)
        axis.annotate(label, (x, y), xytext=offset, textcoords="offset points")


def tpr_fpr_by_cwe(report: dict[str, Any], config: Config) -> Figure:
    scenarios = list(report["scenarios"])
    figure, axes = plt.subplots(len(config.cwe_ids), 1, sharex=True, sharey=True)
    figure.set_size_inches(config.report.figures.width_inches, 1.3 * len(config.cwe_ids) + 0.6)
    positions = range(len(scenarios))
    for axis, cwe in zip(axes, config.cwe_ids, strict=True):
        metrics = [report["scenarios"][s]["metrics"][cwe] for s in scenarios]
        tpr = [m["tpr"] or 0 for m in metrics]
        fpr = [m["fpr"] or 0 for m in metrics]
        axis.bar([p - 0.2 for p in positions], tpr, width=0.38, color=DARK, label="TPR")
        axis.bar(
            [p + 0.2 for p in positions],
            fpr,
            width=0.38,
            color="white",
            edgecolor=DARK,
            hatch="////",
            label="FPR",
        )
        axis.set_ylim(0, 1)
        axis.set_ylabel(cwe)
        axis.grid(axis="y", linewidth=0.3, color=LIGHT)
        axis.set_axisbelow(True)
    axes[0].legend(ncols=2, loc="upper left", bbox_to_anchor=(0, 1.25))
    axes[-1].set_xticks(list(positions), [_short_name(s) for s in scenarios], rotation=45, ha="right")
    figure.tight_layout()
    return figure


def roc_space(report: dict[str, Any], config: Config) -> Figure:
    figure, axis = plt.subplots()
    width = config.report.figures.width_inches
    figure.set_size_inches(width, width * 0.9)
    axis.plot([0, 1], [0, 1], linestyle="--", linewidth=0.6, color=MID)
    points = [
        (scenario, entry["metrics"]["pooled"]["fpr"], entry["metrics"]["pooled"]["tpr"])
        for scenario, entry in report["scenarios"].items()
    ]
    _plot_labeled_points(axis, [p for p in points if p[1] is not None and p[2] is not None])
    axis.set_xlim(0, 1)
    axis.set_ylim(0, 1)
    axis.set_xlabel("False positive rate")
    axis.set_ylabel("True positive rate")
    axis.set_aspect("equal")
    figure.tight_layout()
    return figure


def sast_action_composition(report: dict[str, Any], config: Config) -> Figure | None:
    models = [s for s, e in report["scenarios"].items() if "sast_action" in e]
    if not models:
        return None
    figure, axis = plt.subplots()
    figure.set_size_inches(config.report.figures.width_inches, 0.45 * len(models) + 1.0)
    for row, scenario in enumerate(models):
        breakdown = report["scenarios"][scenario]["sast_action"]
        left = 0
        for action in ACTIONS:
            counts = breakdown.get(action, {"vulnerable": 0, "not_vulnerable": 0})
            # Benar: konfirmasi dan tambahan pada kasus rentan, penolakan pada kasus tidak rentan.
            correct_label = "not_vulnerable" if action == "rejected" else "vulnerable"
            wrong_label = "vulnerable" if action == "rejected" else "not_vulnerable"
            for label, hatch in ((correct_label, None), (wrong_label, "////")):
                count = counts[label]
                axis.barh(
                    row,
                    count,
                    left=left,
                    color=ACTION_SHADES[action],
                    edgecolor="white",
                    linewidth=0.8,
                    hatch=hatch,
                )
                left += count
    axis.set_yticks(range(len(models)), [_short_name(s) for s in models])
    axis.invert_yaxis()
    axis.set_xlabel("Test cases")
    handles = [plt.Rectangle((0, 0), 1, 1, color=ACTION_SHADES[a]) for a in ACTIONS]
    handles.append(plt.Rectangle((0, 0), 1, 1, facecolor="white", edgecolor=DARK, hatch="////"))
    axis.legend(handles, [*ACTIONS, "wrong"], ncols=2, loc="lower left", bbox_to_anchor=(0, 1.0))
    figure.tight_layout()
    return figure


def cost_vs_score(report: dict[str, Any], config: Config) -> Figure | None:
    scenarios = report["scenarios"]
    costs: dict[str, float] = {}
    for scenario, entry in scenarios.items():
        cost = entry.get("time_cost", {}).get(f"run{entry['run']}")
        if cost and cost["cost_per_case_usd"] is not None:
            costs[scenario] = cost["cost_per_case_usd"]
    if not costs:
        return None
    # A tidak memanggil LLM; ENS tidak memanggil ulang, biayanya jumlah biaya anggotanya.
    costs["A"] = 0.0
    members = [f"B-{m}" for m in config.ensemble.members]
    if "ENS" in scenarios and all(m in costs for m in members):
        costs["ENS"] = sum(costs[m] for m in members)

    points = [
        (scenario, cost, scenarios[scenario]["metrics"]["pooled"]["benchmark_score"])
        for scenario, cost in costs.items()
        if scenarios[scenario]["metrics"]["pooled"]["benchmark_score"] is not None
    ]
    figure, axis = plt.subplots()
    width = config.report.figures.width_inches
    figure.set_size_inches(width, width * 0.75)
    _plot_labeled_points(axis, points)
    axis.set_xlim(left=0)
    axis.set_xlabel("Cost per test case (USD)")
    axis.set_ylabel("Benchmark Score (TPR - FPR)")
    axis.axhline(0, linewidth=0.6, color=MID, linestyle="--")
    figure.tight_layout()
    return figure


def build_figures(report: dict[str, Any], config: Config) -> dict[str, Figure]:
    with plt.rc_context(_style(config)):
        candidates = {
            "fig1_tpr_fpr_by_cwe": tpr_fpr_by_cwe(report, config),
            "fig2_roc_space": roc_space(report, config),
            "fig3_sast_action": sast_action_composition(report, config),
            "fig4_cost_vs_score": cost_vs_score(report, config),
        }
    return {name: figure for name, figure in candidates.items() if figure is not None}


def save_figures(figures: dict[str, Figure], output_dir: Path, file_format: str) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, figure in figures.items():
        path = output_dir / f"{name}.{file_format}"
        figure.savefig(path, format=file_format, bbox_inches="tight")
        paths.append(path)
    return paths


def figure_svg(figure: Figure) -> str:
    buffer = io.StringIO()
    figure.savefig(buffer, format="svg", bbox_inches="tight")
    svg = buffer.getvalue()
    return svg[svg.index("<svg") :]
