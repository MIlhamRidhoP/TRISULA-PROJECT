from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from trisula.__main__ import main
from trisula.config import DEFAULT_CONFIG_PATH, Config, load_config


def load_raw_config() -> dict:
    return yaml.safe_load(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))


def test_repository_config_is_valid():
    config = load_config()
    assert config.cwe_ids == ["CWE-89", "CWE-79"]
    assert config.cwe_by_category == {"sqli": "CWE-89", "xss": "CWE-79"}
    assert config.llm.models["grok"].base_url == "https://api.x.ai/v1"


def test_unknown_active_model_is_rejected():
    raw = load_raw_config()
    raw["llm"]["active_models"] = ["gemini", "claude-x"]
    with pytest.raises(ValidationError, match="unknown models"):
        Config.model_validate(raw)


def test_unknown_ensemble_member_is_rejected():
    raw = load_raw_config()
    raw["ensemble"]["members"] = ["gemini", "gpt", "llama"]
    with pytest.raises(ValidationError, match="unknown models"):
        Config.model_validate(raw)


def test_unknown_provider_is_rejected():
    raw = load_raw_config()
    raw["llm"]["models"]["gpt"]["provider"] = "azure"
    with pytest.raises(ValidationError):
        Config.model_validate(raw)


@pytest.mark.parametrize(
    ("section", "key", "bad_value"),
    [
        (("benchmark", "sample"), "per_category", -10),
        (("llm",), "max_format_retries", -1),
        (("llm", "models", "gemini"), "price_input_per_mtok", -2.0),
        (("llm", "scenarios", "B"), "runs", 0),
    ],
)
def test_negative_or_zero_values_are_rejected(section, key, bad_value):
    raw = load_raw_config()
    target = raw
    for part in section:
        target = target[part]
    target[key] = bad_value
    with pytest.raises(ValidationError):
        Config.model_validate(raw)


def test_min_votes_above_member_count_is_rejected():
    raw = load_raw_config()
    raw["ensemble"]["min_votes"] = 4
    with pytest.raises(ValidationError, match="min_votes"):
        Config.model_validate(raw)


def test_dast_mode_validates_but_cli_refuses_to_run(tmp_path: Path, caplog):
    raw = load_raw_config()
    raw["analysis"]["mode"] = "dast"
    Config.model_validate(raw)
    config_path = tmp_path / "trisula.yml"
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    assert main(["--config", str(config_path), "evaluate"]) == 2
    assert "not implemented" in caplog.text
