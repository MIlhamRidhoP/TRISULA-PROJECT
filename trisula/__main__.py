import argparse
import logging
import os
import sys
from pathlib import Path

from trisula.config import (
    DEFAULT_CONFIG_PATH,
    Config,
    UnsupportedModeError,
    ensure_supported_mode,
    load_config,
)


def _not_implemented(args: argparse.Namespace, config: Config) -> int:
    logging.error("%s: not implemented yet", args.command)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trisula", description="LLM review on top of CodeQL findings.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="path to trisula.yml")
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")

    commands.add_parser("sample", help="sample test cases from OWASP Benchmark")
    commands.add_parser("sanitize", help="remove comments and identifying names from sampled cases")
    commands.add_parser("prefilter", help="select files that may be sent to an LLM")
    commands.add_parser("parse-sarif", help="convert CodeQL SARIF into findings")

    review = commands.add_parser("review", help="ask one model to review the sampled files")
    review.add_argument("--model", required=True)
    review.add_argument("--scenario", required=True, choices=["B", "C"])
    review.add_argument("--run", type=int, help="single run number; default runs all configured runs")
    review.add_argument("--limit", type=int, help="review only the first N files")

    commands.add_parser("ensemble", help="normalize verdicts and build the ensemble scenario")
    commands.add_parser("evaluate", help="compute metrics against ground truth")
    commands.add_parser("report", help="write SARIF, PR comment, HTML report, and figures")
    commands.add_parser("demo", help="run every stage with the mock model on a small local fixture")

    for subparser in commands.choices.values():
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
    except UnsupportedModeError as exc:
        logging.error("%s", exc)
        return 2
    return args.handler(args, config)


if __name__ == "__main__":
    sys.exit(main())
