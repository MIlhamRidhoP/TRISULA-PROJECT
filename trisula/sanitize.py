import csv
import json
import logging
import random
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_java
from tree_sitter import Language, Node, Parser

from trisula.config import Config, SanitizeConfig, TrisulaError
from trisula.sampling import JAVA_SOURCE_ROOT, benchmark_target_dir

log = logging.getLogger(__name__)

JAVA_PARSER = Parser(Language(tree_sitter_java.language()))
COMMENT_NODE_TYPES = {"line_comment", "block_comment"}
ORIGINAL_NAME_PATTERN = re.compile(r"BenchmarkTest\d{5}")
FORBIDDEN_TERMS = ("benchmarktest", "owasp", "benchmark")


class SanitizeError(TrisulaError):
    pass


@dataclass(frozen=True)
class NameMapping:
    original_name: str
    case_id: str
    number: int


def _walk(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _replace_ranges(source: bytes, edits: list[tuple[int, int, bytes]]) -> bytes:
    for start, end, replacement in sorted(edits, reverse=True):
        source = source[:start] + replacement + source[end:]
    return source


def _tidy_blank_lines(text: str) -> str:
    lines = [line.rstrip() for line in text.splitlines()]
    tidy: list[str] = []
    for line in lines:
        if line or (tidy and tidy[-1]):
            tidy.append(line)
    while tidy and not tidy[-1]:
        tidy.pop()
    return "\n".join(tidy) + "\n"


def _comment_span(source: bytes, node: Node) -> tuple[int, int]:
    # Komentar yang menempati baris sendiri dihapus bersama barisnya, bukan meninggalkan baris kosong.
    line_start = source.rfind(b"\n", 0, node.start_byte) + 1
    line_end = source.find(b"\n", node.end_byte)
    line_end = len(source) if line_end == -1 else line_end
    if source[line_start : node.start_byte].strip() or source[node.end_byte : line_end].strip():
        return node.start_byte, node.end_byte
    return line_start, min(line_end + 1, len(source))


def strip_comments(source: str) -> str:
    """Hapus semua node komentar hasil parse tree-sitter, lalu rapikan baris kosong berturut-turut."""
    encoded = source.encode("utf-8")
    tree = JAVA_PARSER.parse(encoded)
    edits = [
        (*_comment_span(encoded, node), b"")
        for node in _walk(tree.root_node)
        if node.type in COMMENT_NODE_TYPES
    ]
    return _tidy_blank_lines(_replace_ranges(encoded, edits).decode("utf-8"))


def replace_servlet_paths(source: str, servlet_path: str) -> str:
    encoded = source.encode("utf-8")
    tree = JAVA_PARSER.parse(encoded)
    edits = []
    for node in _walk(tree.root_node):
        if node.type != "annotation" or node.child_by_field_name("name").text != b"WebServlet":
            continue
        arguments = node.child_by_field_name("arguments")
        for literal in _walk(arguments):
            if literal.type == "string_literal":
                edits.append((literal.start_byte, literal.end_byte, f'"{servlet_path}"'.encode()))
    return _replace_ranges(encoded, edits).decode("utf-8")


def assign_case_ids(original_names: list[str], class_prefix: str, seed: int) -> list[NameMapping]:
    """Nomor baru diacak dengan seed supaya tidak mencerminkan urutan nomor asli."""
    names = sorted(original_names)
    numbers = list(range(1, len(names) + 1))
    random.Random(seed).shuffle(numbers)
    return [
        NameMapping(name, f"{class_prefix}{number:04d}", number)
        for name, number in zip(names, numbers, strict=True)
    ]


def _package_pattern(package: str) -> re.Pattern[str]:
    return re.compile(re.escape(package) + r"(?![\w])")


def _package_of(directory: str) -> str:
    return Path(directory).relative_to(JAVA_SOURCE_ROOT).as_posix().replace("/", ".")


def rename_packages(text: str, renames: list[tuple[str, str]]) -> str:
    for old, new in renames:
        text = _package_pattern(old).sub(new, text)
    return text


def find_forbidden_strings(files: dict[str, str], terms: list[str], allowed: list[str]) -> list[str]:
    allowed_patterns = [re.compile(re.escape(match), re.IGNORECASE) for match in allowed]
    hits = []
    for path, text in sorted(files.items()):
        for number, line in enumerate(text.splitlines(), start=1):
            checked = line
            for pattern in allowed_patterns:
                checked = pattern.sub("", checked)
            lowered = checked.lower()
            hits.extend(f"{path}:{number}: {term}" for term in terms if term in lowered)
    return hits


def sanitize_case(source: str, mapping: dict[str, NameMapping], number: int, settings: SanitizeConfig) -> str:
    text = strip_comments(source)
    text = ORIGINAL_NAME_PATTERN.sub(
        lambda match: mapping[match.group(0)].case_id if match.group(0) in mapping else match.group(0), text
    )
    return replace_servlet_paths(text, f"{settings.servlet_path_prefix}{number:04d}")


def _move_package_dir(java_root: Path, old_package: str, new_package: str) -> None:
    old_dir = java_root / old_package.replace(".", "/")
    new_dir = java_root / new_package.replace(".", "/")
    new_dir.mkdir(parents=True, exist_ok=True)
    for child in list(old_dir.iterdir()):
        shutil.move(str(child), str(new_dir / child.name))
    old_dir.rmdir()
    for parent in old_dir.parents:
        if parent == java_root or any(parent.iterdir()):
            break
        parent.rmdir()


def _read_sample_names(path: Path) -> list[str]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [row["original_name"] for row in csv.DictReader(handle)]


def run_sanitize(config: Config) -> list[NameMapping]:
    """Tahap `sanitize` (DATASET.md bagian 5). Semua perubahan dihitung di memori dan baru ditulis jika lolos
    pemeriksaan, jadi kegagalan tidak meninggalkan target setengah tersanitasi."""
    benchmark = config.benchmark
    if benchmark is None:
        raise SanitizeError("config has no 'benchmark' section")
    settings = benchmark.sanitize
    target = benchmark_target_dir(config)
    testcode_dir = target / benchmark.testcode_dir
    sample_names = _read_sample_names(config.data_dir / "sample_list.csv")
    missing = [name for name in sample_names if not (testcode_dir / f"{name}.java").exists()]
    if missing:
        raise SanitizeError(f"{len(missing)} sampled files not found in {testcode_dir}; run `sample` first")

    mappings = assign_case_ids(sample_names, settings.class_prefix, benchmark.sample.seed)
    by_name = {m.original_name: m for m in mappings}

    testcode_package = _package_of(benchmark.testcode_dir)
    renames = []
    if settings.rename_package:
        renames = [
            (testcode_package, settings.testcode_package_to),
            (settings.package_from, settings.package_to),
        ]
    new_testcode_package = rename_packages(testcode_package, renames)
    new_testcode_dir = target / JAVA_SOURCE_ROOT / new_testcode_package.replace(".", "/")

    sanitized_cases = {}
    for mapping in mappings:
        source = (testcode_dir / f"{mapping.original_name}.java").read_text(encoding="utf-8")
        text = rename_packages(sanitize_case(source, by_name, mapping.number, settings), renames)
        sanitized_cases[f"{mapping.case_id}.java"] = text

    broken = [
        name for name, text in sanitized_cases.items() if JAVA_PARSER.parse(text.encode()).root_node.has_error
    ]
    if broken:
        raise SanitizeError(f"sanitized files do not parse cleanly: {broken[:10]}")

    meta = json.loads((config.data_dir / "sample_meta.json").read_text(encoding="utf-8"))
    terms = sorted({*FORBIDDEN_TERMS, *meta["all_categories"]})
    hits = find_forbidden_strings(sanitized_cases, terms, settings.allowed_matches)
    if hits:
        for hit in hits[:50]:
            log.error("leftover string %s", hit)
        raise SanitizeError(
            f"{len(hits)} leftover identifying strings in sanitized cases; "
            "fix sanitization or list legitimate matches in benchmark.sanitize.allowed_matches"
        )

    for mapping in mappings:
        (testcode_dir / f"{mapping.original_name}.java").unlink()
    for name, text in sanitized_cases.items():
        (testcode_dir / name).write_text(text, encoding="utf-8", newline="\n")
    if renames:
        for path in [*target.rglob("*.java"), target / "pom.xml"]:
            if path.parent == testcode_dir:
                continue
            original = path.read_text(encoding="utf-8")
            renamed = rename_packages(original, renames)
            if renamed != original:
                path.write_text(renamed, encoding="utf-8", newline="\n")
        java_root = target / JAVA_SOURCE_ROOT
        _move_package_dir(java_root, testcode_package, settings.testcode_package_to)
        _move_package_dir(java_root, settings.package_from, settings.package_to)

    mapping_path = config.data_dir / "name_mapping.csv"
    with mapping_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["original_name", "case_id", "new_path"])
        for mapping in mappings:
            new_path = (new_testcode_dir / f"{mapping.case_id}.java").relative_to(config.root)
            writer.writerow([mapping.original_name, mapping.case_id, new_path.as_posix()])

    log.info(
        "sanitized %d cases: comments removed, names mapped, no leftover strings, all files parse -> %s",
        len(mappings),
        mapping_path,
    )
    return mappings
