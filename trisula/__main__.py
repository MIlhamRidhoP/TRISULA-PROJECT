import argparse
import logging
import os
import sys
from pathlib import Path

from trisula.config import DEFAULT_CONFIG_PATH, Config, TrisulaError, ensure_supported_mode, load_config


def _not_implemented(args: argparse.Namespace, config: Config) -> int:
    logging.error("%s: not implemented yet", args.command)
    return 1


def _sample(args: argparse.Namespace, config: Config) -> int:
    from trisula.sampling import run_sample

    run_sample(config, args.source)
    return 0


def _sanitize(args: argparse.Namespace, config: Config) -> int:
    from trisula.sanitize import run_sanitize

    run_sanitize(config)
    return 0


def _parse_sarif(args: argparse.Namespace, config: Config) -> int:
    from trisula.codeql import run_parse_sarif

    codeql_dir = config.results_dir / "codeql"
    sarif_paths = args.sarif or sorted(codeql_dir.glob("*.sarif"))
    run_parse_sarif(config, sarif_paths, args.timing or codeql_dir / "timing.json")
    return 0


def _review(args: argparse.Namespace, config: Config) -> int:
    from trisula.review import run_review

    scenario = config.llm.scenarios.get(args.scenario)
    if scenario is None:
        raise TrisulaError(f"scenario {args.scenario} is not configured")
    runs = [args.run] if args.run else list(range(1, scenario.runs + 1))
    run_review(config, args.model, args.scenario, runs, args.limit)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trisula", description="LLM review on top of CodeQL findings.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="path to trisula.yml")
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")

    sample = commands.add_parser("sample", help="sample test cases from OWASP Benchmark")
    sample.add_argument("--source", type=Path, help="local BenchmarkJava checkout instead of cloning")
    sample.set_defaults(handler=_sample)
    sanitize = commands.add_parser(
        "sanitize", help="remove comments and identifying names from sampled cases"
    )
    sanitize.set_defaults(handler=_sanitize)
    commands.add_parser("prefilter", help="select files that may be sent to an LLM")
    parse_sarif = commands.add_parser("parse-sarif", help="convert CodeQL SARIF into findings")
    parse_sarif.add_argument("--sarif", type=Path, nargs="*", help="default: <results>/codeql/*.sarif")
    parse_sarif.add_argument("--timing", type=Path, help="default: <results>/codeql/timing.json")
    parse_sarif.set_defaults(handler=_parse_sarif)

    review = commands.add_parser("review", help="ask one model to review the sampled files")
    review.add_argument("--model", required=True)
    review.add_argument("--scenario", required=True, choices=["B", "C"])
    review.add_argument("--run", type=int, help="single run number; default runs all configured runs")
    review.add_argument("--limit", type=int, help="review only the first N files")
    review.set_defaults(handler=_review)

    commands.add_parser("ensemble", help="normalize verdicts and build the ensemble scenario")
    commands.add_parser("evaluate", help="compute metrics against ground truth")
    commands.add_parser("report", help="write SARIF, PR comment, HTML report, and figures")
    commands.add_parser("demo", help="run every stage with the mock model on a small local fixture")

    for subparser in commands.choices.values():
        if subparser.get_default("handler") is None:
            subparser.set_defaults(handler=_not_implemented)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("TRISULA_LOG_LEVEL", "INFO").upper(),
        format="%(levelname)s %(name)s: %(message)s",
    )
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    try:
        ensure_supported_mode(config)
        return args.handler(args, config)
    except TrisulaError as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
