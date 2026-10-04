from typing import Any

from trisula.config import Config
from trisula.schema import Finding

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/MIlhamRidhoP/TRISULA-PROJECT"
LEVEL_BY_CONFIDENCE = {"high": "error", "medium": "warning", "low": "note"}


def _rule(cwe_id: str, name: str, description: str) -> dict[str, Any]:
    number = int(cwe_id.split("-")[1])
    return {
        "id": cwe_id,
        "name": name.replace(" ", ""),
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{number}.html",
        # Format tag sama dengan CodeQL supaya GitHub mengelompokkan per CWE.
        "properties": {"tags": ["security", f"external/cwe/cwe-{number:03d}"]},
    }


def model_sarif(
    findings: list[Finding], model_key: str, model_id: str, config: Config, version: str
) -> dict[str, Any]:
    """SARIF 2.1.0 untuk temuan rentan satu model di Skenario B run utama. Putusan fallback tidak ikut."""
    rules = [_rule(cwe.id, cwe.name, cwe.description) for cwe in config.cwes]
    rule_index = {rule["id"]: index for index, rule in enumerate(rules)}
    results = []
    for finding in findings:
        if not finding.vulnerable or finding.fallback:
            continue
        message = finding.reason or f"{finding.cwe} reported by {model_key}."
        if finding.recommendation:
            message = f"{message} Recommendation: {finding.recommendation}"
        results.append(
            {
                "ruleId": finding.cwe,
                "ruleIndex": rule_index[finding.cwe],
                "level": LEVEL_BY_CONFIDENCE.get(finding.confidence or "", "warning"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file, "uriBaseId": "%SRCROOT%"},
                            # Code Scanning butuh baris; putusan tanpa baris ditaruh di baris 1.
                            "region": {"startLine": finding.line or 1},
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.confidence,
                    "scenario": finding.scenario,
                    "run": finding.run,
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": f"trisula-{model_key}",
                        "informationUri": INFORMATION_URI,
                        "semanticVersion": version,
                        "rules": rules,
                        "properties": {"model_id": model_id},
                    }
                },
                "automationDetails": {"id": f"trisula-{model_key}/"},
                "results": results,
            }
        ],
    }
