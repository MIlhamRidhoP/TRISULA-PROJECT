import logging
from pathlib import Path

from trisula.codeql import codeql_findings, load_codeql_results
from trisula.config import Config
from trisula.llm.base import CaseOutcome
from trisula.review import list_review_files, load_outcomes
from trisula.schema import Finding, SastAction

log = logging.getLogger(__name__)


def sast_action(codeql_detected: bool, llm_vulnerable: bool) -> SastAction:
    if codeql_detected:
        return "confirmed" if llm_vulnerable else "rejected"
    return "added" if llm_vulnerable else "none"


def llm_findings(
    outcomes: list[CaseOutcome], codeql: dict[tuple[str, str], Finding], cwe_ids: list[str]
) -> list[Finding]:
    """Ubah putusan satu model menjadi Finding (DESIGN.md bagian 6 dan 7).

    Skenario B jatuh ke putusan CodeQL saat LLM error; skenario C dicatat null dan dinilai tidak rentan."""
    findings = []
    for outcome in outcomes:
        with_hints = outcome.scenario.startswith("B-")
        verdicts = {v.cwe: v for v in outcome.verdicts or []}
        for cwe in cwe_ids:
            baseline = codeql[(outcome.file, cwe)]
            common = {
                "case_id": outcome.case_id,
                "file": outcome.file,
                "cwe": cwe,
                "source": outcome.model_key,
                "scenario": outcome.scenario,
                "run": outcome.run,
            }
            if outcome.error:
                findings.append(
                    Finding(
                        **common,
                        vulnerable=baseline.vulnerable if with_hints else None,
                        line=baseline.line if with_hints else None,
                        error=outcome.error,
                        fallback=with_hints,
                    )
                )
                continue
            verdict = verdicts[cwe]
            findings.append(
                Finding(
                    **common,
                    vulnerable=verdict.vulnerable,
                    line=verdict.line,
                    sast_action=sast_action(bool(baseline.vulnerable), verdict.vulnerable)
                    if with_hints
                    else None,
                    confidence=verdict.confidence,
                    reason=verdict.reason,
                    recommendation=verdict.recommendation,
                )
            )
    return findings


def verdict_files(config: Config) -> list[Path]:
    return sorted((config.results_dir / "verdicts").glob("*-run*.jsonl"))


def build_findings(config: Config) -> list[Finding]:
    """Finding skenario A untuk semua file input LLM, ditambah semua putusan LLM di results/verdicts."""
    files = list_review_files(config)
    known_files = set(files)
    baseline = codeql_findings(load_codeql_results(config).alerts, files, config.cwe_ids)
    codeql_index = {(f.file, f.cwe): f for f in baseline}

    findings = list(baseline)
    for path in verdict_files(config):
        outcomes = [o for o in load_outcomes(path) if o.file in known_files]
        findings.extend(llm_findings(outcomes, codeql_index, config.cwe_ids))
    return findings
