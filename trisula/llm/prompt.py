import re
from dataclasses import dataclass
from pathlib import Path

from trisula.codeql import CodeQLAlert
from trisula.config import Config, TrisulaError

BLOCK_PATTERN = re.compile(r"^```prompt:([\w-]+)\n(.*?)\n```$", re.MULTILINE | re.DOTALL)
VERSION_PATTERN = re.compile(r"^- Versi: `([^`]+)`", re.MULTILINE)
PLACEHOLDER_PATTERN = re.compile(r"\{\{(\w+)\}\}")
# Aturan render di prompts/sast_review.md: jalur aliran data dipotong setelah 15 langkah.
MAX_FLOW_STEPS = 15


class PromptError(TrisulaError):
    pass


@dataclass(frozen=True)
class PromptTemplate:
    version: str
    blocks: dict[str, str]


@dataclass(frozen=True)
class RenderedPrompt:
    system: str
    user: str


def load_prompt_template(path: Path, expected_version: str) -> PromptTemplate:
    text = path.read_text(encoding="utf-8")
    version = VERSION_PATTERN.search(text)
    if version is None:
        raise PromptError(f"{path}: version line not found")
    if version.group(1) != expected_version:
        raise PromptError(
            f"{path} is version {version.group(1)} but llm.prompt_version is {expected_version}; "
            "they must match because the version is part of the cache key"
        )
    return PromptTemplate(version.group(1), dict(BLOCK_PATTERN.findall(text)))


def fill(template: str, values: dict[str, str]) -> str:
    """Ganti placeholder dalam satu lewatan, jadi kode yang memuat `{{x}}` tidak ikut diganti."""

    def lookup(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise PromptError(f"placeholder {{{{{name}}}}} has no value")
        return values[name]

    return PLACEHOLDER_PATTERN.sub(lookup, template)


def number_lines(code: str) -> str:
    lines = code.splitlines()
    width = len(str(len(lines)))
    return "\n".join(f"{number:>{width}} | {line}".rstrip() for number, line in enumerate(lines, start=1))


def render_flow(steps: list[str]) -> str:
    if not steps:
        return "not available"
    shown = steps[:MAX_FLOW_STEPS]
    if len(steps) > MAX_FLOW_STEPS:
        shown.append(f"... ({len(steps) - MAX_FLOW_STEPS} more steps)")
    return "\n".join(shown)


def render_findings(template: PromptTemplate, alerts: list[CodeQLAlert]) -> str:
    if not alerts:
        return template.blocks["no-findings"]
    items = []
    for alert in sorted(alerts, key=lambda a: (a.line or 0, a.rule_id)):
        flow = "\n".join(f"    {line}" for line in render_flow(alert.flow).splitlines())
        values = {
            "rule_id": alert.rule_id,
            "cwe_list": ", ".join(alert.cwes),
            "line": str(alert.line) if alert.line is not None else "unknown",
            "message": alert.message,
            "flow": flow,
        }
        items.append(fill(template.blocks["finding-item"], values))
    return "\n\n".join(items)


def build_prompt(
    template: PromptTemplate,
    config: Config,
    scenario: str,
    file_path: str,
    code: str,
    alerts: list[CodeQLAlert],
) -> RenderedPrompt:
    values = {
        "language": config.project.language_display,
        "cwe_definitions": "\n".join(f"- {cwe.id} ({cwe.name}): {cwe.description}" for cwe in config.cwes),
        "cwe_ids": ", ".join(config.cwe_ids),
        "sast_context": template.blocks[f"sast-context-{scenario}"],
        "file_path": file_path,
        "numbered_code": number_lines(code),
        "line_count": str(len(code.splitlines())),
    }
    if config.llm.scenarios[scenario].with_sast_hints:
        values["sast_findings"] = render_findings(template, alerts)
    return RenderedPrompt(
        system=fill(template.blocks["system"], values),
        user=fill(template.blocks[f"user-{scenario}"], values),
    )
