from pathlib import Path

import pytest

from trisula.codeql import CodeQLAlert
from trisula.llm.prompt import (
    PromptError,
    build_prompt,
    fill,
    load_prompt_template,
    number_lines,
    render_flow,
)

from .conftest import make_config

PROMPT_FILE = Path("prompts/sast_review.md")


@pytest.fixture
def template():
    return load_prompt_template(PROMPT_FILE, "1.0")


def alert(line: int, flow: list[str]) -> CodeQLAlert:
    return CodeQLAlert(
        rule_id="java/sql-injection",
        cwes=["CWE-89"],
        file="a/Case0001.java",
        line=line,
        level="error",
        message="This query depends on a [user-provided value](1).",
        flow=flow,
    )


def test_template_version_must_match_config():
    with pytest.raises(PromptError, match="must match"):
        load_prompt_template(PROMPT_FILE, "2.0")


def test_unfilled_placeholder_is_an_error():
    with pytest.raises(PromptError, match="file_path"):
        fill("File: {{file_path}}", {})


def test_inserted_code_is_not_scanned_for_placeholders():
    assert fill("{{code}}", {"code": 'String s = "{{file_path}}";'}) == 'String s = "{{file_path}}";'


def test_line_numbers_are_right_aligned_to_widest_number():
    code = "\n".join(f"line{n}" if n != 2 else "" for n in range(1, 11))
    numbered = number_lines(code).splitlines()
    assert numbered[0] == " 1 | line1"
    assert numbered[1] == " 2 |"
    assert numbered[9] == "10 | line10"


def test_long_flow_is_cut_after_fifteen_steps():
    steps = [f"line {n}: step" for n in range(1, 21)]
    rendered = render_flow(steps).splitlines()
    assert len(rendered) == 16
    assert rendered[-1] == "... (5 more steps)"


def test_scenario_b_prompt_lists_findings_with_indented_flow(tmp_path, template):
    config = make_config(tmp_path)
    prompt = build_prompt(
        template, config, "B", "a/Case0001.java", "class A {}\n", [alert(1, ["line 1: getParameter(...)"])]
    )
    assert "CodeQL" in prompt.system
    assert "- Rule: java/sql-injection (CWE-89)\n  Location: line 1\n" in prompt.user
    assert "  Data flow:\n    line 1: getParameter(...)\n" in prompt.user
    assert "- CWE-89 (SQL Injection): untrusted data" in prompt.system
    assert "{{" not in prompt.system + prompt.user


def test_scenario_b_without_alerts_says_no_findings(tmp_path, template):
    prompt = build_prompt(template, make_config(tmp_path), "B", "a/Case0001.java", "class A {}\n", [])
    assert "No findings were reported for this file." in prompt.user


def test_scenario_c_prompt_has_no_tool_output(tmp_path, template):
    config = make_config(tmp_path)
    prompt_b = build_prompt(template, config, "B", "a/Case0001.java", "class A {}\n", [alert(1, [])])
    prompt_c = build_prompt(template, config, "C", "a/Case0001.java", "class A {}\n", [alert(1, [])])
    assert "static_analysis_findings" not in prompt_c.user
    assert "CodeQL" not in prompt_c.system
    assert "You are the only security check applied to this file in this step." in prompt_c.system
    # Selain blok konteks, prompt sistem B dan C identik.
    context_b = template.blocks["sast-context-B"]
    context_c = template.blocks["sast-context-C"]
    assert prompt_b.system.replace(context_b, "") == prompt_c.system.replace(context_c, "")
