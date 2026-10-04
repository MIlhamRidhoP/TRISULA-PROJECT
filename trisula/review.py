import json
import logging
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from tenacity.wait import wait_base

from trisula.codeql import load_codeql_results
from trisula.config import Config, TrisulaError
from trisula.llm import create_adapter
from trisula.llm.base import CallLogWriter, CaseOutcome, ReviewCase, Reviewer
from trisula.llm.prompt import load_prompt_template
from trisula.prefilter import load_llm_files

log = logging.getLogger(__name__)


def verdicts_path(config: Config, scenario_name: str, run: int) -> Path:
    return config.results_dir / "verdicts" / f"{scenario_name}-run{run}.jsonl"


def load_outcomes(path: Path) -> list[CaseOutcome]:
    with path.open(encoding="utf-8") as handle:
        return [CaseOutcome.model_validate_json(line) for line in handle if line.strip()]


def run_review(
    config: Config,
    model_key: str,
    scenario: str,
    runs: list[int],
    limit: int | None = None,
    wait: wait_base | None = None,
) -> dict[int, list[CaseOutcome]]:
    if model_key not in config.llm.models:
        raise TrisulaError(f"unknown model {model_key!r}; known: {sorted(config.llm.models)}")
    if scenario not in config.llm.scenarios:
        raise TrisulaError(f"scenario {scenario!r} is not configured under llm.scenarios")
    max_run = config.llm.scenarios[scenario].runs
    if any(not 1 <= run <= max_run for run in runs):
        raise TrisulaError(f"scenario {scenario} has runs 1..{max_run}, got {runs}")

    template = load_prompt_template(config.resolve(config.llm.prompt_file), config.llm.prompt_version)
    alerts_by_file = defaultdict(list)
    if config.llm.scenarios[scenario].with_sast_hints:
        for alert in load_codeql_results(config).alerts:
            alerts_by_file[alert.file].append(alert)

    files = load_llm_files(config)[:limit]
    if not files:
        raise TrisulaError("prefilter left no files to review")
    cases = [
        ReviewCase(file, config.resolve(file).read_text(encoding="utf-8"), alerts_by_file.get(file, []))
        for file in files
    ]
    adapter = create_adapter(config, model_key)
    scenario_name = f"{scenario}-{model_key}"

    outcomes_by_run = {}
    for run in runs:
        call_log = CallLogWriter(config.results_dir / "raw" / f"calls-{scenario}-{model_key}-run{run}.jsonl")
        reviewer = Reviewer(config, scenario, adapter, template, call_log, wait=wait)
        started_at = datetime.now(UTC)
        started = time.perf_counter()
        try:
            with ThreadPoolExecutor(max_workers=config.llm.max_concurrent_requests) as pool:
                outcomes = list(pool.map(reviewer.review, cases, [run] * len(cases)))
        finally:
            call_log.close()
        wall_seconds = time.perf_counter() - started

        output = verdicts_path(config, scenario_name, run)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("".join(o.model_dump_json() + "\n" for o in outcomes), encoding="utf-8")
        errors = [o for o in outcomes if o.error]
        cost = sum(o.cost_usd or 0 for o in outcomes)
        meta = {
            "scenario": scenario_name,
            "model_key": model_key,
            "model_id": adapter.model.model_id,
            "reasoning": adapter.model.reasoning,
            "run": run,
            "cases": len(outcomes),
            "errors": len(errors),
            "format_errors": sum(1 for o in errors if o.error == "invalid_format"),
            "cache_hits": sum(1 for o in outcomes if o.cache_hit),
            "cost_usd": cost,
            "started_at": started_at.isoformat(timespec="seconds"),
            "wall_seconds": wall_seconds,
        }
        output.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        log.info(
            "%s run %d: %d cases, %d errors, %d cache hits, $%.4f, %.1fs -> %s",
            scenario_name,
            run,
            len(outcomes),
            len(errors),
            meta["cache_hits"],
            cost,
            wall_seconds,
            output,
        )
        outcomes_by_run[run] = outcomes
    return outcomes_by_run
