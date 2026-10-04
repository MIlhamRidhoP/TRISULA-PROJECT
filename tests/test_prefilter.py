import json

import pytest

from trisula.prefilter import glob_to_regex, load_llm_files, run_prefilter

from .conftest import make_config

FAKE_AWS_KEY = "AKIA" + "Q3TRISULAFAKE7XY"
FAKE_OPENAI_KEY = "sk-proj-" + "trisulaFakeKey0123456789abcd"
CLEAN_JAVA = "class Clean {\n    int x = 1;\n}\n"
CONTACT_JAVA = (
    'class Contact {\n    String mail = "budi@example.co.id";\n    String hp = "081234567890";\n}\n'
)


@pytest.fixture
def workspace(tmp_path):
    source = tmp_path / "app/src"
    (source / "seed").mkdir(parents=True)
    files = {
        "Clean.java": CLEAN_JAVA,
        "Other.java": CLEAN_JAVA,
        "Keys.java": f'class Keys {{\n    String aws = "{FAKE_AWS_KEY}";\n}}\n',
        "Client.java": f'class Client {{\n    // token\n    String key = "{FAKE_OPENAI_KEY}";\n}}\n',
        "Contact.java": CONTACT_JAVA,
        ".env": f"OPENAI_API_KEY={FAKE_OPENAI_KEY}\n",
        ".env-prod": f"AWS_KEY={FAKE_AWS_KEY}\n",
        "schema.sql": "CREATE TABLE users (id INT);\n",
        "seed/Seeder.java": CLEAN_JAVA,
    }
    for name, text in files.items():
        (source / name).write_text(text, encoding="utf-8")
    return tmp_path


def configure(root, **overrides):
    return make_config(
        root, **{"project.llm_paths": ["app/src"], "project.source_paths": ["app/src"], **overrides}
    )


def reasons_by_file(report: dict) -> dict[str, set[str]]:
    return {
        e["file"].rsplit("/", 1)[-1]: {r.get("type", r["kind"]) for r in e["reasons"]}
        for e in report["excluded"]
    }


def test_sensitive_files_never_reach_llm_input(workspace):
    config = configure(workspace)
    report = run_prefilter(config)
    included = {path.rsplit("/", 1)[-1] for path in load_llm_files(config)}

    assert included == {"Clean.java", "Other.java", "Contact.java"}
    reasons = reasons_by_file(report)
    assert reasons["Keys.java"] == {"aws-access-key"}
    assert reasons["Client.java"] == {"openai-api-key"}
    assert {".env", ".env-prod", "schema.sql"} <= set(reasons)
    assert "exclude_pattern" in reasons["Seeder.java"]


def test_prefilter_report_records_lines_but_not_secret_values(workspace):
    config = configure(workspace)
    run_prefilter(config)
    text = (config.results_dir / "prefilter.json").read_text(encoding="utf-8")
    assert FAKE_AWS_KEY not in text and FAKE_OPENAI_KEY not in text
    assert "budi@example.co.id" not in text and "081234567890" not in text
    entry = next(e for e in json.loads(text)["excluded"] if e["file"].endswith("Keys.java"))
    assert entry["reasons"] == [{"kind": "secret", "type": "aws-access-key", "line": 2}]


def test_pii_only_warns_by_default(workspace):
    report = run_prefilter(configure(workspace))
    warning = next(w for w in report["warnings"] if w["file"].endswith("Contact.java"))
    assert {(r["type"], r["line"]) for r in warning["reasons"]} == {("email", 2), ("phone-id", 3)}


def test_pii_exclude_mode_removes_file(workspace):
    config = configure(workspace, **{"prefilter.pii_mode": "exclude"})
    run_prefilter(config)
    assert not any(path.endswith("Contact.java") for path in load_llm_files(config))


def test_gitleaks_findings_exclude_files(workspace):
    report_path = workspace / "gitleaks.json"
    leak = {"File": "app/src/Other.java", "StartLine": 2, "RuleID": "generic-api-key", "Secret": "REDACTED"}
    report_path.write_text(json.dumps([leak]), encoding="utf-8")
    config = configure(workspace, **{"prefilter.gitleaks": True})

    report = run_prefilter(config, gitleaks_report=report_path)
    assert reasons_by_file(report)["Other.java"] == {"gitleaks:generic-api-key"}
    assert not any(path.endswith("Other.java") for path in load_llm_files(config))


def test_review_refuses_to_run_without_prefilter(tmp_path):
    with pytest.raises(Exception, match="run `prefilter` first"):
        load_llm_files(make_config(tmp_path))


@pytest.mark.parametrize(
    ("pattern", "path", "matches"),
    [
        ("**/.env", ".env", True),
        ("**/.env", "a/b/.env", True),
        ("**/.env.*", "a/.env.local", True),
        ("**/.env.*", "a/.env-prod", False),
        ("**/*.sql", "db/schema.sql", True),
        ("**/test/**", "src/test/Foo.java", True),
        ("**/test/**", "src/latest/Foo.java", False),
        ("*.log", "a/b.log", False),
    ],
)
def test_exclude_globs_follow_gitignore_style(pattern, path, matches):
    assert bool(glob_to_regex(pattern).match(path)) is matches
