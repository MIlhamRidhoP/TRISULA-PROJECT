import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from pydantic import BaseModel

from trisula.config import Config, TrisulaError
from trisula.schema import Finding

log = logging.getLogger(__name__)

CWE_TAG_PATTERN = re.compile(r"^external/cwe/cwe-0*([1-9][0-9]*)$", re.IGNORECASE)


class CodeQLAlert(BaseModel):
    rule_id: str
    cwes: list[str]
    file: str
    line: int | None
    level: str
    message: str
    flow: list[str]


class CodeQLResults(BaseModel):
    query_suite: str
    duration_seconds: float | None
    alerts: list[CodeQLAlert]


def normalize_cwe_tag(tag: str) -> str | None:
    match = CWE_TAG_PATTERN.match(tag)
    return f"CWE-{match.group(1)}" if match else None


def _rule_tables(run: dict[str, Any]) -> tuple[dict[str, dict], list[dict], list[list[dict]]]:
    # CodeQL menaruh rule di driver atau di extensions (query pack). Result bisa merujuk lewat id atau indeks;
    # toolComponent.index menunjuk ke tool.extensions, tanpa toolComponent berarti driver.
    driver_rules = run["tool"]["driver"].get("rules", [])
    extension_rules = [extension.get("rules", []) for extension in run["tool"].get("extensions", [])]
    by_id = {rule["id"]: rule for rules in [driver_rules, *extension_rules] for rule in rules}
    return by_id, driver_rules, extension_rules


def _find_rule(
    result: dict[str, Any],
    by_id: dict[str, dict],
    driver_rules: list[dict],
    extension_rules: list[list[dict]],
) -> dict | None:
    reference = result.get("rule", {})
    rule_id = result.get("ruleId") or reference.get("id")
    if rule_id in by_id:
        return by_id[rule_id]
    if "index" not in reference:
        return None
    if "toolComponent" in reference:
        return extension_rules[reference["toolComponent"]["index"]][reference["index"]]
    return driver_rules[reference["index"]]


def _location_line(location: dict[str, Any]) -> int | None:
    return location.get("physicalLocation", {}).get("region", {}).get("startLine")


def _flow_steps(result: dict[str, Any]) -> list[str]:
    flows = result.get("codeFlows") or []
    if not flows or not flows[0].get("threadFlows"):
        return []
    steps = []
    for step in flows[0]["threadFlows"][0].get("locations", []):
        location = step.get("location", {})
        text = location.get("message", {}).get("text")
        if not text:
            text = location.get("physicalLocation", {}).get("region", {}).get("snippet", {}).get("text", "")
        steps.append(f"line {_location_line(location)}: {text.strip()}")
    return steps


def parse_sarif(sarif: dict[str, Any], cwe_ids: list[str]) -> list[CodeQLAlert]:
    """Alert yang rule-nya bertag CWE dalam cakupan (DESIGN.md bagian 4.2). Tingkat `note` tetap ikut."""
    in_scope = set(cwe_ids)
    alerts = []
    for run in sarif["runs"]:
        by_id, driver_rules, extension_rules = _rule_tables(run)
        for result in run.get("results", []):
            rule = _find_rule(result, by_id, driver_rules, extension_rules)
            if rule is None:
                raise TrisulaError(f"SARIF result references unknown rule {result.get('ruleId')!r}")
            tags = rule.get("properties", {}).get("tags", [])
            cwes = sorted({cwe for cwe in map(normalize_cwe_tag, tags) if cwe in in_scope})
            if not cwes:
                continue
            location = result["locations"][0]
            alerts.append(
                CodeQLAlert(
                    rule_id=rule["id"],
                    cwes=cwes,
                    file=unquote(location["physicalLocation"]["artifactLocation"]["uri"]),
                    line=_location_line(location),
                    level=result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning"),
                    message=result["message"]["text"],
                    flow=_flow_steps(result),
                )
            )
    return alerts


def codeql_findings(alerts: list[CodeQLAlert], files: list[str], cwe_ids: list[str]) -> list[Finding]:
    """Skenario A: satu Finding per file dan CWE. Terdeteksi jika ada minimal satu alert ber-CWE sama."""
    findings = []
    for file in files:
        for cwe in cwe_ids:
            matching = [alert for alert in alerts if alert.file == file and cwe in alert.cwes]
            first_line = min((a.line for a in matching if a.line is not None), default=None)
            findings.append(
                Finding(
                    case_id=Path(file).stem,
                    file=file,
                    cwe=cwe,
                    vulnerable=bool(matching),
                    line=first_line,
                    source="codeql",
                    scenario="A",
                    run=1,
                    reason="; ".join(sorted({a.message for a in matching})) or None,
                )
            )
    return findings


def alerts_path(config: Config) -> Path:
    return config.results_dir / "codeql" / "alerts.json"


def load_codeql_results(config: Config) -> CodeQLResults:
    path = alerts_path(config)
    if not path.exists():
        raise TrisulaError(f"{path} not found; run `parse-sarif` first")
    return CodeQLResults.model_validate_json(path.read_text(encoding="utf-8"))


def run_parse_sarif(config: Config, sarif_paths: list[Path], timing_path: Path | None) -> CodeQLResults:
    if not sarif_paths:
        raise TrisulaError("no SARIF files given")
    alerts = []
    for path in sarif_paths:
        alerts.extend(parse_sarif(json.loads(path.read_text(encoding="utf-8")), config.cwe_ids))

    duration = None
    if timing_path is not None and timing_path.exists():
        duration = json.loads(timing_path.read_text(encoding="utf-8"))["duration_seconds"]
    results = CodeQLResults(
        query_suite=config.analysis.codeql.query_suite, duration_seconds=duration, alerts=alerts
    )
    output = alerts_path(config)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(results.model_dump_json(indent=2), encoding="utf-8")

    per_cwe = ", ".join(f"{cwe}={sum(cwe in a.cwes for a in alerts)}" for cwe in config.cwe_ids)
    log.info(
        "parsed %d in-scope alerts (%s) from %d SARIF files -> %s",
        len(alerts),
        per_cwe,
        len(sarif_paths),
        output,
    )
    return results
