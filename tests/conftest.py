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
