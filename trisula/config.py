from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeFloat,
    NonNegativeInt,
    PositiveFloat,
    PositiveInt,
    model_validator,
)

DEFAULT_CONFIG_PATH = Path("config/trisula.yml")

# Ekstensi file per bahasa CodeQL, dipakai prefilter untuk memilih input LLM (DESIGN.md bagian 11).
LANGUAGE_EXTENSIONS = {
    "java": (".java",),
    "javascript": (".ts", ".tsx", ".js", ".jsx"),
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProjectConfig(StrictModel):
    name: str
    language: Literal["java", "javascript"]
    language_display: str
    source_paths: list[str] = Field(min_length=1)
    llm_paths: list[str] = Field(min_length=1)
    exclude: list[str] = []


class SampleConfig(StrictModel):
    per_category: PositiveInt
    vulnerable_ratio: float = Field(ge=0, le=1)
    seed: int


class SanitizeConfig(StrictModel):
    class_prefix: str
    servlet_path_prefix: str
    rename_package: bool
    package_from: str
    package_to: str
    testcode_package_to: str
    allowed_matches: list[str] = []


class BenchmarkConfig(StrictModel):
    repo: str
    ref: str
    expected_results: str
    testcode_dir: str
    helpers_dir: str
    sample: SampleConfig
    sanitize: SanitizeConfig


class CodeQLConfig(StrictModel):
    query_suite: str
    build_mode: Literal["none", "manual", "autobuild"]


class AnalysisConfig(StrictModel):
    mode: Literal["sast", "dast", "both"]
    sast_tool: Literal["codeql"]
    codeql: CodeQLConfig


class CweConfig(StrictModel):
    id: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    name: str
    benchmark_category: str
    description: str


class ScenarioConfig(StrictModel):
    runs: PositiveInt
    with_sast_hints: bool


class ModelConfig(StrictModel):
    provider: Literal["google", "openai", "mock"]
    model_id: str
    api_key_env: str | None = None
    base_url: str | None = None
    reasoning: str
    price_input_per_mtok: NonNegativeFloat
    price_output_per_mtok: NonNegativeFloat
    invalid_response_rate: float = Field(default=0.0, ge=0, le=1)

    @model_validator(mode="after")
    def _real_providers_need_key(self) -> "ModelConfig":
        if self.provider != "mock" and not self.api_key_env:
            raise ValueError(f"model {self.model_id!r} needs api_key_env")
        return self


class LLMConfig(StrictModel):
    prompt_file: str
    prompt_version: str
    scenarios: dict[Literal["B", "C"], ScenarioConfig]
    primary_run: PositiveInt
    max_network_retries: NonNegativeInt
    max_format_retries: NonNegativeInt
    max_output_tokens: PositiveInt
    request_timeout_seconds: PositiveFloat
    max_concurrent_requests: PositiveInt
    models: dict[str, ModelConfig]
    active_models: list[str]

    @model_validator(mode="after")
    def _check_references(self) -> "LLMConfig":
        unknown = [key for key in self.active_models if key not in self.models]
        if unknown:
            raise ValueError(f"active_models references unknown models: {unknown}")
        for name, scenario in self.scenarios.items():
            if self.primary_run > scenario.runs:
                raise ValueError(f"primary_run {self.primary_run} exceeds runs of scenario {name}")
        return self


class EnsembleConfig(StrictModel):
    members: list[str] = Field(min_length=1)
    run: PositiveInt
    min_votes: PositiveInt


class EvaluationConfig(StrictModel):
    alpha: float = Field(gt=0, lt=1)
    multiple_comparison: Literal["holm"]
    mcnemar_exact_below: PositiveInt
    sensitivity_majority_runs: bool


class PrefilterConfig(StrictModel):
    gitleaks: bool
    pii_mode: Literal["warn", "exclude"]


class FiguresConfig(StrictModel):
    format: Literal["pdf", "png", "svg"]
    width_inches: PositiveFloat
    font_size: PositiveFloat


class ReportConfig(StrictModel):
    pr_comment: bool
    max_pr_findings: PositiveInt
    sarif: bool
    html: bool
    figures: FiguresConfig


class PathsConfig(StrictModel):
    cache: str
    data: str
    targets: str
    results: str


class Config(StrictModel):
    project: ProjectConfig
    # Hanya dibutuhkan untuk eksperimen OWASP Benchmark (sample dan sanitize).
    benchmark: BenchmarkConfig | None = None
    analysis: AnalysisConfig
    cwes: list[CweConfig] = Field(min_length=1)
    llm: LLMConfig
    ensemble: EnsembleConfig
    evaluation: EvaluationConfig
    prefilter: PrefilterConfig
    report: ReportConfig
    paths: PathsConfig
    # Semua path relatif di konfigurasi diselesaikan terhadap root. Demo memakai root terpisah.
    root: Path = Field(default=Path("."), exclude=True)

    @model_validator(mode="after")
    def _check_cross_references(self) -> "Config":
        ids = [cwe.id for cwe in self.cwes]
        if len(set(ids)) != len(ids):
            raise ValueError(f"duplicate CWE ids: {ids}")
        unknown = [key for key in self.ensemble.members if key not in self.llm.models]
        if unknown:
            raise ValueError(f"ensemble.members references unknown models: {unknown}")
        if self.ensemble.min_votes > len(self.ensemble.members):
            raise ValueError("ensemble.min_votes exceeds the number of members")
        if "B" in self.llm.scenarios and self.ensemble.run > self.llm.scenarios["B"].runs:
            raise ValueError("ensemble.run exceeds runs of scenario B")
        return self

    @property
    def cwe_ids(self) -> list[str]:
        return [cwe.id for cwe in self.cwes]

    @property
    def cwe_by_category(self) -> dict[str, str]:
        return {cwe.benchmark_category: cwe.id for cwe in self.cwes}

    def resolve(self, path: str | Path) -> Path:
        path = Path(path)
        return path if path.is_absolute() else self.root / path

    @property
    def data_dir(self) -> Path:
        return self.resolve(self.paths.data)

    @property
    def results_dir(self) -> Path:
        return self.resolve(self.paths.results)

    @property
    def cache_dir(self) -> Path:
        return self.resolve(self.paths.cache)

    @property
    def targets_dir(self) -> Path:
        return self.resolve(self.paths.targets)


class UnsupportedModeError(Exception):
    pass


def load_config(path: Path = DEFAULT_CONFIG_PATH, root: Path = Path(".")) -> Config:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Config.model_validate({**raw, "root": root})


def ensure_supported_mode(config: Config) -> None:
    if config.analysis.mode != "sast":
        raise UnsupportedModeError(
            f"analysis.mode {config.analysis.mode!r} is not implemented yet; only 'sast' is supported"
        )
