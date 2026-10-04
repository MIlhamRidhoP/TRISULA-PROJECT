import csv
import json

import pytest

from trisula.ensemble import run_ensemble
from trisula.evaluate import evaluate
from trisula.review import run_review

from .conftest import MOCK_MEMBERS, mock_ensemble_overrides, prepare_workspace


@pytest.fixture
def evaluated(tmp_path):
    config = prepare_workspace(tmp_path, **mock_ensemble_overrides())
    for model in MOCK_MEMBERS:
        run_review(config, model, "B", [1, 2, 3])
    run_review(config, "mock-a", "C", [1])
    run_ensemble(config)
    return config, evaluate(config)


def test_codeql_baseline_matches_hand_count(evaluated):
    # Dari fixture SARIF: sqli TP=2 (Case0006, Case0008), FP=1 (Case0007), FN=1 (Case0003);
    # xss TP=3, FP=1 (Case0002), FN=0. Masing-masing 3 kasus aman.
    _, report = evaluated
    pooled = report["scenarios"]["A"]["metrics"]["pooled"]
    assert (pooled["tp"], pooled["fp"], pooled["fn"], pooled["tn"]) == (5, 2, 1, 4)
    assert pooled["benchmark_score"] == pytest.approx(5 / 6 - 2 / 6)
    sqli = report["scenarios"]["A"]["metrics"]["CWE-89"]
    assert (sqli["tp"], sqli["fp"], sqli["fn"], sqli["tn"]) == (2, 1, 1, 2)
    assert report["codeql"]["duration_seconds"] == 84.0


def test_report_covers_all_scenarios_and_comparisons(evaluated):
    _, report = evaluated
    assert list(report["scenarios"]) == ["A", "B-mock-a", "B-mock-b", "B-mock-c", "C-mock-a", "ENS"]
    pairs = {(c["first"], c["second"]) for c in report["mcnemar"]}
    assert {("A", "B-mock-a"), ("A", "ENS"), ("B-mock-a", "C-mock-a")} <= pairs
    assert any(c["first"] == "ENS" and c["question"].startswith("RQ2") for c in report["mcnemar"])
    assert all(c["p_holm"] >= c["p_value"] for c in report["mcnemar"])


def test_repeated_runs_report_spread_consistency_and_majority(evaluated):
    _, report = evaluated
    entry = report["scenarios"]["B-mock-a"]
    assert set(entry["across_runs"]["pooled"]["tpr"]) == {"mean", "sd"}
    assert entry["consistency"]["runs"] == [1, 2, 3]
    assert 0 <= entry["consistency"]["flip_rate"] <= 1
    assert "majority_of_runs" in entry
    assert sum(sum(labels.values()) for labels in entry["sast_action"].values()) == 12
    assert entry["time_cost"]["run1"]["calls"] >= 12


def test_output_files_are_written(evaluated):
    config, _ = evaluated
    with (config.results_dir / "per_case.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 12
    assert {"A/run1", "B-mock-a/run3", "ENS/run1"} <= set(rows[0])
    summary = json.loads((config.results_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["primary_run"] == 1
    assert (
        (config.results_dir / "summary.csv").read_text(encoding="utf-8").startswith("scenario,scope,cwe,n,tp")
    )


def test_demo_runs_every_stage_offline(tmp_path, monkeypatch):
    for variable in ("GEMINI_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY"):
        monkeypatch.delenv(variable, raising=False)
    from trisula.config import DEFAULT_CONFIG_PATH
    from trisula.demo import run_demo

    report = run_demo(DEFAULT_CONFIG_PATH, root=tmp_path / "demo")
    assert report.exists()
    summary = json.loads((tmp_path / "demo/results/summary.json").read_text(encoding="utf-8"))
    assert "ENS" in summary["scenarios"]
    assert summary["scenarios"]["A"]["metrics"]["pooled"]["tp"] == 5
