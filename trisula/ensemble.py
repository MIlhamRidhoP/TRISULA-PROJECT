import logging
from collections import Counter
from pathlib import Path

from trisula.config import Config, TrisulaError
from trisula.normalize import build_findings
from trisula.schema import Finding

log = logging.getLogger(__name__)


def ensemble_findings(findings: list[Finding], members: list[str], run: int, min_votes: int) -> list[Finding]:
    """Voting dari B-<member> pada satu run (DESIGN.md bagian 3).

    Putusan error tidak ikut voting. Jika putusan valid kurang dari min_votes, dipakai putusan CodeQL."""
    member_scenarios = {f"B-{member}" for member in members}
    votes: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        if finding.scenario in member_scenarios and finding.run == run and finding.error is None:
            votes.setdefault((finding.case_id, finding.cwe), []).append(finding)

    ensemble = []
    for baseline in (f for f in findings if f.scenario == "A"):
        valid = votes.get((baseline.case_id, baseline.cwe), [])
        yes = [f for f in valid if f.vulnerable]
        common = {"case_id": baseline.case_id, "file": baseline.file, "cwe": baseline.cwe}
        if len(valid) < min_votes:
            ensemble.append(
                Finding(
                    **common,
                    vulnerable=baseline.vulnerable,
                    line=baseline.line,
                    source="ensemble",
                    scenario="ENS",
                    run=run,
                    reason=f"only {len(valid)} valid votes, using CodeQL",
                    fallback=True,
                )
            )
            continue
        voters = ", ".join(sorted(f.source for f in yes)) or "none"
        ensemble.append(
            Finding(
                **common,
                vulnerable=len(yes) >= min_votes,
                line=next((f.line for f in yes if f.line is not None), None),
                source="ensemble",
                scenario="ENS",
                run=run,
                reason=f"{len(yes)} of {len(valid)} models voted vulnerable ({voters})",
            )
        )
    return ensemble


def findings_path(config: Config) -> Path:
    return config.results_dir / "findings.jsonl"


def load_findings(config: Config) -> list[Finding]:
    path = findings_path(config)
    if not path.exists():
        raise TrisulaError(f"{path} not found; run `ensemble` first")
    with path.open(encoding="utf-8") as handle:
        return [Finding.model_validate_json(line) for line in handle if line.strip()]


def run_ensemble(config: Config) -> list[Finding]:
    findings = build_findings(config)
    settings = config.ensemble
    available = {f.scenario for f in findings if f.run == settings.run}
    missing = [m for m in settings.members if f"B-{m}" not in available]
    if missing:
        log.warning("skipping ENS: no B run %d verdicts for %s", settings.run, ", ".join(missing))
    else:
        findings.extend(ensemble_findings(findings, settings.members, settings.run, settings.min_votes))

    path = findings_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f.model_dump_json() + "\n" for f in findings), encoding="utf-8")
    per_scenario = Counter(f"{f.scenario}/run{f.run}" for f in findings)
    log.info(
        "wrote %d findings (%s) -> %s",
        len(findings),
        ", ".join(f"{name}={count}" for name, count in sorted(per_scenario.items())),
        path,
    )
    return findings
