import csv
import json
import logging
import random
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from trisula.config import BenchmarkConfig, Config, SampleConfig, TrisulaError

log = logging.getLogger(__name__)

# File di root BenchmarkJava yang dipertahankan selain src/main/java. Sisanya tidak dibutuhkan untuk
# kompilasi maupun analisis CodeQL (DATASET.md bagian 4).
KEPT_ROOT_FILES = ("pom.xml",)
JAVA_SOURCE_ROOT = Path("src/main/java")


class SamplingError(TrisulaError):
    pass


@dataclass(frozen=True)
class ExpectedResult:
    name: str
    category: str
    vulnerable: bool
    cwe: str


def read_expected_results(path: Path) -> list[ExpectedResult]:
    results = []
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            name, category, vulnerable, cwe = (field.strip() for field in row[:4])
            if vulnerable not in ("true", "false"):
                raise SamplingError(
                    f"{path}: unexpected 'real vulnerability' value {vulnerable!r} for {name}"
                )
            results.append(ExpectedResult(name, category, vulnerable == "true", f"CWE-{int(cwe)}"))
    return results


def select_sample(
    expected: list[ExpectedResult], cwe_by_category: dict[str, str], sample: SampleConfig
) -> list[ExpectedResult]:
    """Sampling berstrata per kategori dan label, deterministik terhadap seed (DATASET.md bagian 3)."""
    for case in expected:
        wanted_cwe = cwe_by_category.get(case.category)
        if wanted_cwe is not None and case.cwe != wanted_cwe:
            raise SamplingError(
                f"{case.name} has category {case.category} but {case.cwe}, expected {wanted_cwe}; "
                "the expected results file does not match the assumed format or version"
            )

    rng = random.Random(sample.seed)
    vulnerable_count = round(sample.per_category * sample.vulnerable_ratio)
    wanted = {True: vulnerable_count, False: sample.per_category - vulnerable_count}
    selected = []
    for category in cwe_by_category:
        for label in (True, False):
            candidates = sorted(
                (case for case in expected if case.category == category and case.vulnerable == label),
                key=lambda case: case.name,
            )
            label_name = "vulnerable" if label else "safe"
            log.info("candidates %s/%s: %d", category, label_name, len(candidates))
            if len(candidates) < wanted[label]:
                raise SamplingError(
                    f"need {wanted[label]} {label_name} {category} cases, only {len(candidates)} available"
                )
            rng.shuffle(candidates)
            selected.extend(candidates[: wanted[label]])
    return sorted(selected, key=lambda case: case.name)


def count_candidates(expected: list[ExpectedResult], categories: list[str]) -> dict[str, dict[str, int]]:
    return {
        category: {
            "vulnerable": sum(1 for c in expected if c.category == category and c.vulnerable),
            "safe": sum(1 for c in expected if c.category == category and not c.vulnerable),
        }
        for category in categories
    }


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def fetch_benchmark(benchmark: BenchmarkConfig, checkout_dir: Path) -> str:
    """Clone BenchmarkJava sekali ke cache lalu checkout ref yang dikunci. Mengembalikan hash commit."""
    if not (checkout_dir / ".git").exists():
        log.info("cloning %s -> %s", benchmark.repo, checkout_dir)
        checkout_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--quiet", benchmark.repo, str(checkout_dir)], check=True)
    try:
        _git("rev-parse", "--verify", "--quiet", f"{benchmark.ref}^{{commit}}", cwd=checkout_dir)
    except subprocess.CalledProcessError:
        _git("fetch", "--quiet", "origin", cwd=checkout_dir)
    _git("checkout", "--quiet", "--detach", benchmark.ref, cwd=checkout_dir)
    return _git("rev-parse", "HEAD", cwd=checkout_dir)


def build_trimmed_project(
    source_dir: Path, target_dir: Path, testcode_dir: str, sample: list[ExpectedResult]
) -> list[str]:
    """Salin pom.xml dan src/main/java, test case hanya yang tersampel. Mengembalikan path yang dibuang."""
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)

    sampled_files = {f"{case.name}.java" for case in sample}
    testcode_path = (source_dir / testcode_dir).resolve()

    def skip_unsampled(directory: str, names: list[str]) -> list[str]:
        if Path(directory).resolve() != testcode_path:
            return []
        return [name for name in names if name.endswith(".java") and name not in sampled_files]

    for name in KEPT_ROOT_FILES:
        shutil.copy2(source_dir / name, target_dir / name)
    shutil.copytree(source_dir / JAVA_SOURCE_ROOT, target_dir / JAVA_SOURCE_ROOT, ignore=skip_unsampled)

    missing = sorted(name for name in sampled_files if not (target_dir / testcode_dir / name).exists())
    if missing:
        raise SamplingError(f"sampled cases missing from {testcode_dir}: {missing[:5]}")

    dropped = [p.name for p in source_dir.iterdir() if p.name not in (*KEPT_ROOT_FILES, "src", ".git")]
    dropped += [
        f"src/{p.relative_to(source_dir / 'src').as_posix()}"
        for p in (source_dir / "src").glob("*/*")
        if p.relative_to(source_dir) != JAVA_SOURCE_ROOT
    ]
    return sorted(dropped)


def benchmark_target_dir(config: Config) -> Path:
    return config.targets_dir / "benchmark"


def write_sample_list(sample: list[ExpectedResult], cwe_by_category: dict[str, str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["original_name", "category", "cwe", "vulnerable"])
        for case in sample:
            writer.writerow(
                [case.name, case.category, cwe_by_category[case.category], str(case.vulnerable).lower()]
            )


def run_sample(config: Config, source_dir: Path | None = None) -> list[ExpectedResult]:
    """Tahap `sample`. Tanpa source_dir, BenchmarkJava diunduh ke cache sesuai benchmark.ref."""
    benchmark = config.benchmark
    if benchmark is None:
        raise SamplingError("config has no 'benchmark' section")
    if source_dir is None:
        source_dir = config.cache_dir / "benchmark" / "BenchmarkJava"
        commit = fetch_benchmark(benchmark, source_dir)
    elif (source_dir / ".git").exists():
        commit = _git("rev-parse", "HEAD", cwd=source_dir)
    else:
        commit = f"local:{source_dir.as_posix()}"
    log.info("benchmark source %s at %s", source_dir, commit)

    expected = read_expected_results(source_dir / benchmark.expected_results)
    cwe_by_category = config.cwe_by_category
    sample = select_sample(expected, cwe_by_category, benchmark.sample)
    dropped = build_trimmed_project(source_dir, benchmark_target_dir(config), benchmark.testcode_dir, sample)
    log.info("dropped from trimmed project: %s", ", ".join(dropped) or "nothing")

    write_sample_list(sample, cwe_by_category, config.data_dir / "sample_list.csv")
    meta = {
        "benchmark_repo": benchmark.repo,
        "benchmark_ref": benchmark.ref,
        "benchmark_commit": commit,
        "seed": benchmark.sample.seed,
        "candidates": count_candidates(expected, list(cwe_by_category)),
        "all_categories": sorted({case.category for case in expected}),
        "dropped_paths": dropped,
    }
    (config.data_dir / "sample_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    composition = ", ".join(
        f"{category}={sum(1 for c in sample if c.category == category)}" for category in cwe_by_category
    )
    log.info("sampled %d cases (%s) -> %s", len(sample), composition, config.data_dir / "sample_list.csv")
    return sample
