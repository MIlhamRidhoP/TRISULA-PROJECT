import csv
import itertools
import json
import logging
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trisula.codeql import load_codeql_results
from trisula.config import Config, TrisulaError
from trisula.ensemble import load_findings
from trisula.schema import Finding
from trisula.stats import ConfusionMetrics, count_confusion, holm_adjust, mcnemar_test

log = logging.getLogger(__name__)

POOLED = "pooled"
METRIC_NAMES = ("tpr", "fpr", "precision", "f1", "accuracy", "benchmark_score")


@dataclass(frozen=True)
class Truth:
    cwe: str
    vulnerable: bool


def load_ground_truth(config: Config) -> dict[str, Truth]:
    """Gabungkan sample_list.csv dan name_mapping.csv menjadi label per case_id."""
    mapping_path = config.data_dir / "name_mapping.csv"
    sample_path = config.data_dir / "sample_list.csv"
    for path in (mapping_path, sample_path):
        if not path.exists():
            raise TrisulaError(f"{path} not found; run `sample` and `sanitize` first")
    with sample_path.open(encoding="utf-8", newline="") as handle:
        labels = {row["original_name"]: row for row in csv.DictReader(handle)}
    with mapping_path.open(encoding="utf-8", newline="") as handle:
        return {
            row["case_id"]: Truth(
                labels[row["original_name"]]["cwe"], labels[row["original_name"]]["vulnerable"] == "true"
            )
            for row in csv.DictReader(handle)
        }


def scenario_sort_key(scenario: str) -> tuple[int, str]:
    order = {"A": 0, "B": 1, "C": 2, "ENS": 3}
    return order.get(scenario.split("-", 1)[0], 4), scenario


def predicted(finding: Finding) -> bool:
    # Putusan null (error di Skenario C) dihitung tidak rentan (DESIGN.md bagian 7).
    return bool(finding.vulnerable)


class FindingIndex:
    def __init__(self, findings: list[Finding], truth: dict[str, Truth]):
        self.truth = truth
        self.by_key = {(f.scenario, f.run, f.case_id, f.cwe): f for f in findings}
        self.runs: dict[str, set[int]] = defaultdict(set)
        for finding in findings:
            self.runs[finding.scenario].add(finding.run)

    @property
    def scenarios(self) -> list[str]:
        return sorted(self.runs, key=scenario_sort_key)

    def primary_run(self, scenario: str, primary: int) -> int:
        # A hanya punya run 1 dan ENS memakai run ensemble; skenario lain memakai primary_run.
        runs = self.runs[scenario]
        return primary if primary in runs else min(runs)

    def category_findings(self, scenario: str, run: int) -> dict[str, Finding]:
        """Finding pada CWE kategori tiap test case saja (DESIGN.md bagian 2)."""
        selected = {}
        for case_id, truth in self.truth.items():
            finding = self.by_key.get((scenario, run, case_id, truth.cwe))
            if finding is not None:
                selected[case_id] = finding
        return selected


def metrics_by_cwe(
    predictions: dict[str, bool], truth: dict[str, Truth], cwe_ids: list[str]
) -> dict[str, ConfusionMetrics]:
    results = {}
    for cwe in [*cwe_ids, POOLED]:
        pairs = [
            (predictions[case_id], truth[case_id].vulnerable)
            for case_id in predictions
            if cwe == POOLED or truth[case_id].cwe == cwe
        ]
        results[cwe] = count_confusion(pairs)
    return results


def run_statistics(per_run: list[dict[str, ConfusionMetrics]], cwe_ids: list[str]) -> dict[str, Any]:
    stats: dict[str, Any] = {}
    for cwe in [*cwe_ids, POOLED]:
        stats[cwe] = {}
        for name in METRIC_NAMES:
            values = [getattr(run[cwe], name) for run in per_run]
            if any(value is None for value in values):
                stats[cwe][name] = {"mean": None, "sd": None}
                continue
            stats[cwe][name] = {"mean": statistics.mean(values), "sd": statistics.stdev(values)}
    return stats


def majority_predictions(index: FindingIndex, scenario: str) -> dict[str, bool]:
    runs = sorted(index.runs[scenario])
    per_run = [index.category_findings(scenario, run) for run in runs]
    common = set.intersection(*(set(r) for r in per_run))
    return {case_id: sum(predicted(r[case_id]) for r in per_run) * 2 > len(runs) for case_id in common}


def consistency(index: FindingIndex, scenario: str) -> dict[str, Any]:
    runs = sorted(index.runs[scenario])
    per_run = [index.category_findings(scenario, run) for run in runs]
    common = sorted(set.intersection(*(set(r) for r in per_run)))
    verdicts = {case_id: [predicted(r[case_id]) for r in per_run] for case_id in common}
    flips = sum(1 for values in verdicts.values() if len(set(values)) > 1)
    agreements = [
        sum(1 for values in verdicts.values() if values[i] == values[j]) / len(common)
        for i, j in itertools.combinations(range(len(runs)), 2)
    ]
    return {
        "runs": runs,
        "cases": len(common),
        "flip_rate": flips / len(common) if common else None,
        "pairwise_agreement": statistics.mean(agreements) if agreements and common else None,
    }


def sast_action_breakdown(findings: dict[str, Finding], truth: dict[str, Truth]) -> dict[str, dict[str, int]]:
    breakdown: dict[str, dict[str, int]] = {}
    for case_id, finding in findings.items():
        action = finding.sast_action or "error"
        label = "vulnerable" if truth[case_id].vulnerable else "not_vulnerable"
        breakdown.setdefault(action, {"vulnerable": 0, "not_vulnerable": 0})[label] += 1
    return breakdown


def error_summary(findings: dict[str, Finding]) -> dict[str, Any]:
    kinds = Counter(f.error for f in findings.values() if f.error)
    total = len(findings)
    return {
        "cases": total,
        "errors": sum(kinds.values()),
        "error_rate": sum(kinds.values()) / total if total else None,
        "by_kind": dict(kinds),
    }


def off_category_alerts(index: FindingIndex, scenario: str, run: int) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for (s, r, case_id, cwe), finding in index.by_key.items():
        truth = index.truth.get(case_id)
        if s == scenario and r == run and truth is not None and cwe != truth.cwe and finding.vulnerable:
            counts[cwe] += 1
    return dict(counts)


def _read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def time_and_cost(
    config: Config, scenario: str, run: int, cases: int, codeql_seconds: float | None
) -> dict | None:
    letter, model_key = scenario.split("-", 1)
    calls_path = config.results_dir / "raw" / f"calls-{letter}-{model_key}-run{run}.jsonl"
    meta_path = config.results_dir / "verdicts" / f"{scenario}-run{run}.meta.json"
    if not calls_path.exists():
        return None
    calls = _read_jsonl(calls_path)
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    cost = sum(call["cost_usd"] or 0 for call in calls)
    latency_seconds = sum(call["latency_ms"] or 0 for call in calls) / 1000
    wall = meta.get("wall_seconds")
    return {
        "model_id": meta.get("model_id"),
        "reasoning": meta.get("reasoning"),
        "calls": len(calls),
        "cache_hits": sum(1 for call in calls if call["cache_hit"]),
        "input_tokens": sum(call["input_tokens"] or 0 for call in calls),
        "output_tokens": sum(call["output_tokens"] or 0 for call in calls),
        "cost_usd": cost,
        "cost_per_case_usd": cost / cases if cases else None,
        "llm_latency_seconds": latency_seconds,
        "latency_per_case_seconds": latency_seconds / cases if cases else None,
        "wall_seconds": wall,
        "pipeline_seconds": codeql_seconds + wall
        if letter == "B" and codeql_seconds is not None and wall is not None
        else None,
    }


def correctness(findings: dict[str, Finding], truth: dict[str, Truth]) -> dict[str, bool]:
    return {case_id: predicted(f) == truth[case_id].vulnerable for case_id, f in findings.items()}


def mcnemar_comparisons(
    primary: dict[str, dict[str, Finding]],
    truth: dict[str, Truth],
    pooled_scores: dict[str, float | None],
    config: Config,
) -> list[dict[str, Any]]:
    """Pasangan uji DESIGN.md bagian 4.8, run utama, gabungan kedua CWE, dengan koreksi Holm."""
    b_scenarios = [s for s in primary if s.startswith("B-")]
    pairs = [("A", s, "RQ1") for s in b_scenarios]
    if "ENS" in primary:
        pairs.append(("A", "ENS", "RQ1/RQ2"))
    pairs += [(s, f"C-{s[2:]}", "RQ3") for s in b_scenarios if f"C-{s[2:]}" in primary]
    scored = [s for s in b_scenarios if pooled_scores.get(s) is not None]
    if "ENS" in primary and scored:
        best = max(scored, key=lambda s: pooled_scores[s])
        pairs.append(("ENS", best, "RQ2 (best single model)"))

    comparisons = []
    for first, second, question in pairs:
        if first not in primary or second not in primary:
            continue
        first_correct = correctness(primary[first], truth)
        second_correct = correctness(primary[second], truth)
        common = sorted(set(first_correct) & set(second_correct))
        b = sum(1 for c in common if first_correct[c] and not second_correct[c])
        c = sum(1 for c in common if not first_correct[c] and second_correct[c])
        test = mcnemar_test(b, c, config.evaluation.mcnemar_exact_below)
        comparisons.append(
            {
                "first": first,
                "second": second,
                "question": question,
                "cases": len(common),
                "b_first_only_correct": test.b,
                "c_second_only_correct": test.c,
                "method": test.method,
                "statistic": test.statistic,
                "p_value": test.p_value,
            }
        )
    adjusted = holm_adjust([c["p_value"] for c in comparisons], config.evaluation.alpha)
    for comparison, p_adjusted in zip(comparisons, adjusted, strict=True):
        comparison["p_holm"] = p_adjusted
        comparison["significant"] = p_adjusted < config.evaluation.alpha
    return comparisons


def _metric_rows(scenario: str, scope: str, metrics: dict[str, ConfusionMetrics]) -> list[dict[str, Any]]:
    return [
        {"scenario": scenario, "scope": scope, "cwe": cwe, "n": m.tp + m.fp + m.fn + m.tn, **m.as_dict()}
        for cwe, m in metrics.items()
    ]


def null_metric_notes(rows: list[dict[str, Any]]) -> list[str]:
    return [
        f"{row['scenario']} {row['scope']} {row['cwe']}: {name} is null (zero denominator)"
        for row in rows
        for name in METRIC_NAMES
        if row[name] is None
    ]


def evaluate(config: Config) -> dict[str, Any]:
    truth = load_ground_truth(config)
    index = FindingIndex(load_findings(config), truth)
    codeql = load_codeql_results(config)
    cwe_ids = config.cwe_ids

    summary_rows: list[dict[str, Any]] = []
    primary: dict[str, dict[str, Finding]] = {}
    report: dict[str, Any] = {
        "codeql": {"query_suite": codeql.query_suite, "duration_seconds": codeql.duration_seconds},
        "primary_run": config.llm.primary_run,
        "scenarios": {},
    }
    for scenario in index.scenarios:
        run = index.primary_run(scenario, config.llm.primary_run)
        findings = index.category_findings(scenario, run)
        primary[scenario] = findings
        metrics = metrics_by_cwe({c: predicted(f) for c, f in findings.items()}, truth, cwe_ids)
        summary_rows += _metric_rows(scenario, f"run{run}", metrics)
        entry: dict[str, Any] = {
            "run": run,
            "metrics": {cwe: m.as_dict() for cwe, m in metrics.items()},
            "errors": error_summary(findings),
            "fallbacks": sum(1 for f in findings.values() if f.fallback),
            "off_category_alerts": off_category_alerts(index, scenario, run),
        }
        runs = sorted(index.runs[scenario])
        if scenario.startswith("B-"):
            entry["sast_action"] = sast_action_breakdown(findings, truth)
        if scenario.startswith(("B-", "C-")):
            entry["time_cost"] = {
                f"run{r}": time_and_cost(
                    config, scenario, r, len(index.category_findings(scenario, r)), codeql.duration_seconds
                )
                for r in runs
            }
        if scenario.startswith("B-") and len(runs) > 1:
            per_run = [
                metrics_by_cwe(
                    {c: predicted(f) for c, f in index.category_findings(scenario, r).items()}, truth, cwe_ids
                )
                for r in runs
            ]
            entry["across_runs"] = run_statistics(per_run, cwe_ids)
            entry["consistency"] = consistency(index, scenario)
            if config.evaluation.sensitivity_majority_runs:
                majority = metrics_by_cwe(majority_predictions(index, scenario), truth, cwe_ids)
                entry["majority_of_runs"] = {cwe: m.as_dict() for cwe, m in majority.items()}
                summary_rows += _metric_rows(scenario, "majority", majority)
        report["scenarios"][scenario] = entry

    pooled_scores = {s: e["metrics"][POOLED]["benchmark_score"] for s, e in report["scenarios"].items()}
    report["mcnemar"] = mcnemar_comparisons(primary, truth, pooled_scores, config)
    report["notes"] = null_metric_notes(summary_rows)

    output = config.results_dir
    output.mkdir(parents=True, exist_ok=True)
    with (output / "summary.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(summary_rows)
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_per_case(output / "per_case.csv", index, truth)

    best = max(
        (s for s in pooled_scores if pooled_scores[s] is not None),
        key=lambda s: pooled_scores[s],
        default=None,
    )
    log.info(
        "evaluated %d scenarios on %d cases, best pooled score %s -> %s",
        len(index.scenarios),
        len(truth),
        f"{best}={pooled_scores[best]:.3f}" if best else "n/a",
        output / "summary.json",
    )
    return report


def write_per_case(path: Path, index: FindingIndex, truth: dict[str, Truth]) -> None:
    columns = [(s, r) for s in index.scenarios for r in sorted(index.runs[s])]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["case_id", "cwe", "label", *(f"{s}/run{r}" for s, r in columns)])
        for case_id in sorted(truth):
            row: list[Any] = [case_id, truth[case_id].cwe, int(truth[case_id].vulnerable)]
            for scenario, run in columns:
                finding = index.by_key.get((scenario, run, case_id, truth[case_id].cwe))
                row.append("" if finding is None else int(predicted(finding)))
            writer.writerow(row)
