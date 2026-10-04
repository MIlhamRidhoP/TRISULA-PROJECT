import csv

import pytest

from trisula.sampling import run_sample
from trisula.sanitize import (
    COMMENT_NODE_TYPES,
    JAVA_PARSER,
    SanitizeError,
    _walk,
    assign_case_ids,
    find_leftover_strings,
    replace_servlet_paths,
    run_sanitize,
    strip_comments,
)

from .conftest import BENCHMARK_MINI, make_config


def sanitized_cases(config) -> dict[str, str]:
    cases_dir = config.resolve(config.project.llm_paths[0])
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(cases_dir.glob("*.java"))}


@pytest.fixture
def sanitized_config(mini_config):
    run_sample(mini_config, source_dir=BENCHMARK_MINI)
    run_sanitize(mini_config)
    return mini_config


def test_no_original_names_or_comments_remain(sanitized_config):
    cases = sanitized_cases(sanitized_config)
    assert len(cases) == 12
    for name, text in cases.items():
        assert "BenchmarkTest" not in text, name
        tree = JAVA_PARSER.parse(text.encode())
        assert not any(node.type in COMMENT_NODE_TYPES for node in _walk(tree.root_node)), name


def test_servlet_paths_hide_category(sanitized_config):
    for name, text in sanitized_cases(sanitized_config).items():
        servlet_line = next(line for line in text.splitlines() if line.startswith("@WebServlet"))
        assert "sqli" not in servlet_line and "xss" not in servlet_line
        assert servlet_line.startswith('@WebServlet(value = "/case/'), name


def test_sanitized_files_parse_without_error_nodes(sanitized_config):
    for name, text in sanitized_cases(sanitized_config).items():
        assert not JAVA_PARSER.parse(text.encode()).root_node.has_error, name


def test_package_is_renamed_across_trimmed_project(sanitized_config):
    java_root = sanitized_config.targets_dir / "benchmark/src/main/java"
    assert not (java_root / "org").exists()
    helper = java_root / "com/example/webapp/helpers/DatabaseHelper.java"
    assert "package com.example.webapp.helpers;" in helper.read_text(encoding="utf-8")
    for text in sanitized_cases(sanitized_config).values():
        assert "package com.example.webapp.cases;" in text
        assert "owasp" not in text.lower()


def test_name_mapping_is_complete_and_unique(sanitized_config):
    with (sanitized_config.data_dir / "name_mapping.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 12
    assert len({row["case_id"] for row in rows}) == 12
    for row in rows:
        assert sanitized_config.resolve(row["new_path"]).exists()
        assert row["new_path"].endswith(f"/cases/{row['case_id']}.java")


def test_comment_markers_inside_string_literals_survive():
    source = 'class A {\n    // gone\n    String s = "http://x /* keep */ // keep"; /* gone too */\n}\n'
    assert strip_comments(source) == 'class A {\n    String s = "http://x /* keep */ // keep";\n}\n'


def test_comment_removal_collapses_blank_lines():
    source = "/** header */\n\npackage a;\n\n// one\n\n// two\n\nclass B {}\n"
    assert strip_comments(source) == "package a;\n\nclass B {}\n"


def test_case_numbers_are_shuffled_but_reproducible():
    names = [f"BenchmarkTest{n:05d}" for n in range(1, 21)]
    first = assign_case_ids(names, "Case", seed=42)
    assert first == assign_case_ids(names, "Case", seed=42)
    assert [m.case_id for m in first] != [f"Case{n:04d}" for n in range(1, 21)]
    assert sorted(m.number for m in first) == list(range(1, 21))


CATEGORIES = ["cmdi", "hash", "sqli", "xss"]


def test_dispatcher_path_loses_category_segment():
    source = (
        'class A {\n    void f() {\n        r.getRequestDispatcher("/sqli-02/Case0001.html");\n    }\n}\n'
    )
    sanitized = replace_servlet_paths(source, "/case/0001", "/case/", CATEGORIES)
    assert 'r.getRequestDispatcher("/case/Case0001.html");' in sanitized


def test_servlet_annotation_is_replaced_whole_and_other_literals_untouched():
    source = '@WebServlet(value = "/xss-01/Case0002")\nclass B {\n    String s = "a/sqli-like/b";\n}\n'
    sanitized = replace_servlet_paths(source, "/case/0002", "/case/", CATEGORIES)
    assert '@WebServlet(value = "/case/0002")' in sanitized
    assert '"a/sqli-like/b"' in sanitized


def leftovers(code: str, allowed: list[str] | None = None) -> list[str]:
    return find_leftover_strings({"Case0001.java": code}, ["sqli", "xss"], allowed or [])


def test_library_names_are_not_leftovers():
    code = (
        "class A {\n"
        "    java.util.HashMap<String, String> m = new java.util.HashMap<>();\n"
        "    String e = org.owasp.esapi.ESAPI.encoder().encodeForHTML(p);\n"
        '    String h = crypto.hashCode() + "";\n'
        "}\n"
    )
    assert leftovers(code) == []


def test_in_scope_category_in_string_literal_is_reported_unless_allowed():
    code = 'class A {\n    void f() {\n        r.setHeader("X-XSS-Protection", "0");\n    }\n}\n'
    assert leftovers(code) == ['Case0001.java:3: xss | r.setHeader("X-XSS-Protection", "0");']
    assert leftovers(code, allowed=["X-XSS-Protection"]) == []


def test_category_as_identifier_outside_literals_is_not_reported():
    assert leftovers("class A {\n    int xssCount = 0;\n}\n") == []


def test_category_as_package_segment_is_reported():
    assert leftovers("import com.example.sqli.Helper;\nclass A {}\n") == [
        "Case0001.java:1: sqli | import com.example.sqli.Helper;"
    ]


@pytest.mark.parametrize(
    ("line", "pattern"),
    [
        ("String s = BenchmarkTest00001.class.getName();", "benchmarktest"),
        ("import org.owasp.benchmark.helpers.Utils;", "owasp.benchmark"),
        ('String p = "src/org/owasp/benchmark/x";', "org/owasp/benchmark"),
        ('String p = "/benchmark/index.html";', "benchmark"),
    ],
)
def test_benchmark_identifiers_are_reported(line, pattern):
    hits = leftovers(f"class A {{\n    {line}\n}}\n")
    assert any(f": {pattern} |" in hit for hit in hits)


def test_benchmark_inside_longer_identifier_is_not_reported():
    assert leftovers("class A {\n    int benchmarking = 1;\n}\n") == []


def test_leftover_strings_stop_sanitize_and_leave_target_untouched(tmp_path):
    config = make_config(tmp_path, **{"benchmark.sanitize.allowed_matches": []})
    run_sample(config, source_dir=BENCHMARK_MINI)
    testcode = config.targets_dir / "benchmark" / config.benchmark.testcode_dir
    before = sorted(p.name for p in testcode.iterdir())

    with pytest.raises(SanitizeError, match="leftover"):
        run_sanitize(config)
    assert sorted(p.name for p in testcode.iterdir()) == before
    assert not (config.data_dir / "name_mapping.csv").exists()
