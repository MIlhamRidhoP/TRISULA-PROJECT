import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from trisula.config import LANGUAGE_EXTENSIONS, Config, TrisulaError

log = logging.getLogger(__name__)

# Pola kunci dengan format khas provider. Dipakai di samping Gitleaks supaya file berisi kunci tetap
# tertahan saat Gitleaks tidak terpasang (misalnya saat menjalankan lokal).
SECRET_PATTERNS = {
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "openai-api-key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "xai-api-key": re.compile(r"\bxai-[A-Za-z0-9]{20,}"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
}
# DESIGN.md bagian 11 butir 4: email, nomor telepon Indonesia, dan deret 16 digit (kemungkinan NIK).
PII_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone-id": re.compile(r"(?<![\w+])(?:\+62\s?|0)8\d{7,11}(?!\d)"),
    "16-digit-number": re.compile(r"(?<!\d)\d{16}(?!\d)"),
}


@dataclass
class FileDecision:
    file: str
    excluded: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Glob gaya gitignore: `**/` cocok dengan nol atau lebih folder, `*` tidak melewati `/`."""
    regex = ""
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            regex += "(?:.*/)?"
            index += 3
        elif pattern.startswith("**", index):
            regex += ".*"
            index += 2
        elif pattern[index] == "*":
            regex += "[^/]*"
            index += 1
        elif pattern[index] == "?":
            regex += "[^/]"
            index += 1
        else:
            regex += re.escape(pattern[index])
            index += 1
    return re.compile(f"^{regex}$")


def scan_lines(text: str, patterns: dict[str, re.Pattern[str]], kind: str) -> list[dict[str, Any]]:
    """Catat jenis dan nomor baris saja. Nilai yang cocok sengaja tidak disimpan."""
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        hits.extend(
            {"kind": kind, "type": name, "line": number} for name, p in patterns.items() if p.search(line)
        )
    return hits


def read_gitleaks_report(path: Path, root: Path) -> dict[str, list[dict[str, Any]]]:
    findings: dict[str, list[dict[str, Any]]] = {}
    for leak in json.loads(path.read_text(encoding="utf-8") or "[]"):
        file = Path(leak["File"])
        resolved = (file if file.is_absolute() else root / file).resolve()
        findings.setdefault(str(resolved), []).append(
            {"kind": "secret", "type": f"gitleaks:{leak['RuleID']}", "line": leak.get("StartLine")}
        )
    return findings


def run_gitleaks(scan_dirs: list[Path], root: Path) -> dict[str, list[dict[str, Any]]]:
    findings: dict[str, list[dict[str, Any]]] = {}
    with tempfile.TemporaryDirectory() as temporary:
        for index, directory in enumerate(scan_dirs):
            report = Path(temporary) / f"gitleaks-{index}.json"
            command = [
                "gitleaks",
                "dir",
                str(directory),
                "--report-format",
                "json",
                "--report-path",
                str(report),
            ]
            subprocess.run(
                [*command, "--redact", "--exit-code", "0", "--no-banner", "--log-level", "error"], check=True
            )
            for file, leaks in read_gitleaks_report(report, root).items():
                findings.setdefault(file, []).extend(leaks)
    return findings


def prefilter_path(config: Config) -> Path:
    return config.results_dir / "prefilter.json"


def run_prefilter(config: Config, gitleaks_report: Path | None = None) -> dict[str, Any]:
    """Tahap prefilter (DESIGN.md bagian 11): tentukan file yang boleh dikirim ke LLM."""
    extensions = LANGUAGE_EXTENSIONS[config.project.language]
    excludes = [glob_to_regex(pattern) for pattern in config.project.exclude]
    scan_dirs = [config.resolve(path) for path in config.project.llm_paths]
    missing = [str(d) for d in scan_dirs if not d.is_dir()]
    if missing:
        raise TrisulaError(f"llm_paths not found: {missing}")

    if not config.prefilter.gitleaks:
        gitleaks_status, leaks = "disabled", {}
    elif gitleaks_report is not None:
        gitleaks_status, leaks = (
            f"report:{gitleaks_report.as_posix()}",
            read_gitleaks_report(gitleaks_report, config.root),
        )
    elif shutil.which("gitleaks"):
        gitleaks_status, leaks = "binary", run_gitleaks(scan_dirs, config.root)
    else:
        log.warning("gitleaks not found; only built-in key patterns are checked")
        gitleaks_status, leaks = "not installed", {}

    decisions = []
    for path in sorted(p for directory in scan_dirs for p in directory.rglob("*") if p.is_file()):
        relative = path.relative_to(config.root).as_posix()
        decision = FileDecision(relative)
        if path.suffix not in extensions:
            decision.excluded.append({"kind": "extension", "type": path.suffix or "none"})
        if any(pattern.match(relative) for pattern in excludes):
            decision.excluded.append({"kind": "exclude_pattern"})
        if not decision.excluded:
            text = path.read_text(encoding="utf-8", errors="replace")
            decision.excluded += leaks.get(str(path.resolve()), [])
            decision.excluded += scan_lines(text, SECRET_PATTERNS, "secret")
            pii = scan_lines(text, PII_PATTERNS, "pii")
            if config.prefilter.pii_mode == "exclude":
                decision.excluded += pii
            else:
                decision.warnings += pii
        decisions.append(decision)

    included = [d.file for d in decisions if not d.excluded]
    report = {
        "gitleaks": gitleaks_status,
        "pii_mode": config.prefilter.pii_mode,
        "included": included,
        "excluded": [{"file": d.file, "reasons": d.excluded} for d in decisions if d.excluded],
        "warnings": [{"file": d.file, "reasons": d.warnings} for d in decisions if d.warnings],
    }
    output = prefilter_path(config)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    log.info(
        "prefilter: %d files for LLM, %d excluded, %d with PII warnings (gitleaks: %s) -> %s",
        len(included),
        len(report["excluded"]),
        len(report["warnings"]),
        gitleaks_status,
        output,
    )
    return report


def load_llm_files(config: Config) -> list[str]:
    path = prefilter_path(config)
    if not path.exists():
        raise TrisulaError(f"{path} not found; run `prefilter` first so no unchecked file reaches an LLM")
    return json.loads(path.read_text(encoding="utf-8"))["included"]
