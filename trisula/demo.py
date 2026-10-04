import logging
import shutil
from pathlib import Path

import yaml

from trisula.codeql import run_parse_sarif
from trisula.config import Config, TrisulaError
from trisula.ensemble import run_ensemble
from trisula.evaluate import evaluate
from trisula.prefilter import run_prefilter
from trisula.report.build import run_report
from trisula.review import run_review
from trisula.sampling import run_sample
from trisula.sanitize import run_sanitize

log = logging.getLogger(__name__)

DEMO_DATA = Path(__file__).resolve().parent.parent / "demo"
DEMO_ROOT = Path(".cache/demo")
DEMO_MEMBERS = ["mock-a", "mock-b", "mock-c"]
# Fixture berisi 8 kasus per kategori; 6 per kategori menyisakan kandidat yang tidak terpilih.
DEMO_PER_CATEGORY = 6


def demo_config(config_path: Path, root: Path) -> Config:
    """Konfigurasi repositori dengan tiga salinan adaptor mock sebagai anggota ensemble dan sampel kecil."""
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    models = raw["llm"]["models"]
    if "mock" not in models:
        raise TrisulaError(f"{config_path} has no 'mock' model; the demo needs it")
    for key in DEMO_MEMBERS:
        models[key] = dict(models["mock"])
    raw["llm"]["active_models"] = DEMO_MEMBERS
    raw["llm"]["prompt_file"] = str(Path(raw["llm"]["prompt_file"]).resolve())
    raw["ensemble"]["members"] = DEMO_MEMBERS
    raw["benchmark"]["sample"]["per_category"] = DEMO_PER_CATEGORY
    raw["prefilter"]["gitleaks"] = False
    return Config.model_validate({**raw, "root": root})


def run_demo(config_path: Path, root: Path = DEMO_ROOT) -> Path:
    """Semua tahap dengan adaptor mock pada fixture lokal. Tidak butuh jaringan maupun API key."""
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    config = demo_config(config_path, root)

    run_sample(config, source_dir=DEMO_DATA / "benchmark_mini")
    run_sanitize(config)
    run_prefilter(config)
    run_parse_sarif(config, [DEMO_DATA / "codeql.sarif"], DEMO_DATA / "codeql_timing.json")
    for model_key in DEMO_MEMBERS:
        for scenario, settings in config.llm.scenarios.items():
            run_review(config, model_key, scenario, list(range(1, settings.runs + 1)))
    run_ensemble(config)
    evaluate(config)
    run_report(config)

    report = config.results_dir / "report.html"
    log.info("demo finished -> %s", report)
    return report
