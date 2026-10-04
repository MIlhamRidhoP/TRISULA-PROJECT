from pathlib import Path

import pytest
import yaml

from trisula.config import DEFAULT_CONFIG_PATH, Config

FIXTURES = Path(__file__).parent / "fixtures"
BENCHMARK_MINI = FIXTURES / "benchmark_mini"


def make_config(root: Path, **overrides) -> Config:
    """Konfigurasi repositori dengan root di tmp_path dan sampel kecil sesuai fixture benchmark_mini."""
    raw = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
    raw["benchmark"]["sample"]["per_category"] = 6
    raw["benchmark"]["sanitize"]["allowed_matches"] = ["X-XSS-Protection"]
    raw["llm"]["prompt_file"] = str(Path(raw["llm"]["prompt_file"]).resolve())
    # Tes tidak bergantung pada Gitleaks terpasang; pola kunci bawaan tetap berjalan.
    raw["prefilter"]["gitleaks"] = False
    for dotted, value in overrides.items():
        *parents, key = dotted.split(".")
        target = raw
        for part in parents:
            target = target[part]
        target[key] = value
    return Config.model_validate({**raw, "root": root})


@pytest.fixture
def mini_config(tmp_path: Path) -> Config:
    return make_config(tmp_path)


def prepare_workspace(root: Path, **overrides) -> Config:
    """Fixture benchmark_mini yang sudah disampling, disanitasi, dan punya alerts.json dari SARIF fixture."""
    from trisula.codeql import run_parse_sarif
    from trisula.prefilter import run_prefilter
    from trisula.sampling import run_sample
    from trisula.sanitize import run_sanitize

    config = make_config(root, **overrides)
    run_sample(config, source_dir=BENCHMARK_MINI)
    run_sanitize(config)
    run_prefilter(config)
    run_parse_sarif(config, [FIXTURES / "codeql/demo.sarif"], FIXTURES / "codeql/timing.json")
    return config


MOCK_MEMBERS = ["mock-a", "mock-b", "mock-c"]


def mock_ensemble_overrides() -> dict:
    mock = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))["llm"]["models"]["mock"]
    overrides = {f"llm.models.{key}": dict(mock) for key in MOCK_MEMBERS}
    overrides["ensemble.members"] = MOCK_MEMBERS
    overrides["llm.active_models"] = MOCK_MEMBERS
    return overrides
