from collections import Counter

from trisula.report import DeveloperFinding

# Alasan dari LLM bisa panjang; komentar PR cukup memuat kalimat pertama yang dipotong.
MAX_REASON_CHARS = 240


def _short(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_REASON_CHARS else text[: MAX_REASON_CHARS - 3].rstrip() + "..."


def render_pr_comment(findings: list[DeveloperFinding], max_findings: int, report_url: str | None) -> str:
    """Komentar PR sesuai DESIGN.md bagian 10."""
    per_source = Counter(source for finding in findings for source in finding.sources)
    lines = ["## TRISULA security review", ""]
    if not findings:
        lines.append("No SQL injection or XSS findings from CodeQL or the LLM reviewers.")
    else:
        lines += ["| Source | Findings |", "|---|---|"]
        lines += [f"| {source} | {count} |" for source, count in sorted(per_source.items())]
        lines += [
            "",
            f"Top {min(max_findings, len(findings))} of {len(findings)} findings, most agreed first:",
            "",
        ]
        for finding in findings[:max_findings]:
            location = f"{finding.file}:{finding.line}" if finding.line else finding.file
            lines.append(f"### `{location}` {finding.cwe}")
            lines.append(f"- Reported by: {', '.join(sorted(finding.sources))}")
            if finding.confidence:
                lines.append(f"- LLM confidence: {finding.confidence}")
            reason = next(
                (
                    finding.reasons[s]
                    for s in sorted(finding.sources)
                    if s != "codeql" and s in finding.reasons
                ),
                None,
            )
            reason = reason or finding.reasons.get("codeql")
            if reason:
                lines.append(f"- Why: {_short(reason)}")
            if finding.recommendation:
                lines.append(f"- Fix: {_short(finding.recommendation)}")
            lines.append("")
    lines.append(
        f"Full report: {report_url}" if report_url else "Full report: see the `report` workflow artifact."
    )
    return "\n".join(lines).rstrip() + "\n"
