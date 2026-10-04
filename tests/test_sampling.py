import csv
from pathlib import Path

import pytest

from trisula.config import SampleConfig
from trisula.sampling import (
    ExpectedResult,
    SamplingError,
    benchmark_target_dir,
    read_expected_results,
    run_sample,
    select_sample,
)

from .conftest import BENCHMARK_MINI

CWE_BY_CATEGORY = {"sqli": "CWE-89", "xss": "CWE-79"}


def write_expected_csv(path: Path, per_group: int = 10) -> Path:
    lines = ["# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1"]
    number = 0
    for category, cwe in [("sqli", 89), ("xss", 79), ("cmdi", 78)]:
        for label in ("true", "false"):
            for _ in range(per_group):
                number += 1
                lines.append(f"BenchmarkTest{number:05d},{category},{label},{cwe}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_sample_composition_follows_config(tmp_path: Path):
    expected = read_expected_results(write_expected_csv(tmp_path / "expected.csv"))
    sample = select_sample(
        expected, CWE_BY_CATEGORY, SampleConfig(per_category=8, vulnerable_ratio=0.25, seed=1)
    )

    counts = {(c.category, c.vulnerable): 0 for c in sample}
    for case in sample:
        counts[(case.category, case.vulnerable)] += 1
    assert counts == {("sqli", True): 2, ("sqli", False): 6, ("xss", True): 2, ("xss", False): 6}


def test_same_seed_gives_identical_sample(tmp_path: Path):
    expected = read_expected_results(write_expected_csv(tmp_path / "expected.csv"))
    config = SampleConfig(per_category=6, vulnerable_ratio=0.5, seed=42)
    first = select_sample(expected, CWE_BY_CATEGORY, config)
    second = select_sample(list(reversed(expected)), CWE_BY_CATEGORY, config)
    assert first == second


def test_different_seed_gives_different_sample(tmp_path: Path):
    expected = read_expected_results(write_expected_csv(tmp_path / "expected.csv"))
    first = select_sample(
        expected, CWE_BY_CATEGORY, SampleConfig(per_category=6, vulnerable_ratio=0.5, seed=1)
    )
    second = select_sample(
        expected, CWE_BY_CATEGORY, SampleConfig(per_category=6, vulnerable_ratio=0.5, seed=2)
    )
    assert first != second


def test_not_enough_candidates_stops_with_available_count(tmp_path: Path):
    expected = read_expected_results(write_expected_csv(tmp_path / "expected.csv", per_group=3))
    with pytest.raises(SamplingError, match="only 3 available"):
        select_sample(expected, CWE_BY_CATEGORY, SampleConfig(per_category=10, vulnerable_ratio=0.5, seed=1))


def test_category_with_unexpected_cwe_stops_sampling():
    expected = [ExpectedResult("BenchmarkTest00001", "sqli", True, "CWE-564")]
    with pytest.raises(SamplingError, match="CWE-564"):
        select_sample(expected, CWE_BY_CATEGORY, SampleConfig(per_category=1, vulnerable_ratio=1, seed=1))


def test_run_sample_builds_trimmed_project(mini_config):
    sample = run_sample(mini_config, source_dir=BENCHMARK_MINI)

    target = benchmark_target_dir(mini_config)
    testcode = target / mini_config.benchmark.testcode_dir
    assert sorted(p.stem for p in testcode.glob("*.java")) == [case.name for case in sample]
    assert (target / mini_config.benchmark.helpers_dir / "DatabaseHelper.java").exists()
    assert (target / "pom.xml").exists()
    assert not (target / "src/main/webapp").exists()

    with (mini_config.data_dir / "sample_list.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 12
    assert {row["cwe"] for row in rows if row["category"] == "xss"} == {"CWE-79"}
    assert all(row["category"] != "cmdi" for row in rows)
