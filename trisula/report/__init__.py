from dataclasses import dataclass, field

from trisula.schema import Finding

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, None: 0}


@dataclass
class DeveloperFinding:
    """Satu (file, CWE) yang dilaporkan minimal satu sumber: CodeQL atau model di Skenario B run utama."""

    file: str
    case_id: str
    cwe: str
    line: int | None = None
    sources: list[str] = field(default_factory=list)
    confidence: str | None = None
    reasons: dict[str, str] = field(default_factory=dict)
    recommendation: str | None = None

    @property
    def agreement(self) -> int:
        return len(self.sources)


def developer_findings(findings: list[Finding], primary_run: int) -> list[DeveloperFinding]:
    """Gabungkan temuan rentan per file dan CWE, diurutkan menurut jumlah sumber yang sepakat lalu keyakinan.

    Putusan fallback tidak dihitung sebagai suara model karena isinya salinan putusan CodeQL."""
    grouped: dict[tuple[str, str], DeveloperFinding] = {}
    for finding in findings:
        is_codeql = finding.scenario == "A"
        is_llm = finding.scenario.startswith("B-") and finding.run == primary_run and not finding.fallback
        if not finding.vulnerable or not (is_codeql or is_llm):
            continue
        entry = grouped.setdefault(
            (finding.file, finding.cwe),
            DeveloperFinding(file=finding.file, case_id=finding.case_id, cwe=finding.cwe),
        )
        entry.sources.append(finding.source)
        entry.line = entry.line or finding.line
        if finding.reason:
            entry.reasons[finding.source] = finding.reason
        if is_llm and CONFIDENCE_RANK[finding.confidence] > CONFIDENCE_RANK[entry.confidence]:
            entry.confidence = finding.confidence
            entry.recommendation = finding.recommendation or entry.recommendation
    return sorted(
        grouped.values(),
        key=lambda f: (-f.agreement, -CONFIDENCE_RANK[f.confidence], f.file, f.cwe),
    )
