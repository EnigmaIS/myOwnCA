from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTATION_ROOTS = (ROOT / "docs", ROOT / "archive" / "docs", ROOT / "tls")
ROOT_DOCUMENTS = (ROOT / "README.md", ROOT / "setup.md")
FENCE_RE = re.compile(r"^ {0,3}(?P<fence>`{3,}|~{3,})")
LINK_RE = re.compile(r"!?(?<!\\!)\[[^]]*\]\((?P<target>[^)]+)\)")
SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
SOURCE_LINE_RE = re.compile(r"^(?P<path>.+):(?P<line>[1-9][0-9]*)$")
HOST_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/")


def _markdown_files() -> list[Path]:
    files = list(ROOT_DOCUMENTS)
    for directory in DOCUMENTATION_ROOTS:
        files.extend(directory.rglob("*.md"))
    return sorted(files)


def _non_fenced_lines(document: Path) -> list[tuple[int, str]]:
    active_fence = ""
    result: list[tuple[int, str]] = []
    for number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), start=1):
        match = FENCE_RE.match(line)
        if active_fence:
            if match and match.group("fence")[0] == active_fence[0]:
                active_fence = ""
            continue
        if match:
            active_fence = match.group("fence")
            continue
        result.append((number, line))
    return result


def _local_target(target: str, document: Path) -> Path | None:
    value = unquote(target.strip())
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    if not value or value.startswith("#") or SCHEME_RE.match(value):
        return None
    if value.startswith("/"):
        raise ValueError("absolute local link")
    value = value.split("#", maxsplit=1)[0].split("?", maxsplit=1)[0]
    candidate = (document.parent / value).resolve()
    if candidate.exists():
        return candidate
    source_line = SOURCE_LINE_RE.match(value)
    if source_line:
        candidate = (document.parent / source_line.group("path")).resolve()
        if candidate.is_file() and len(candidate.read_text(encoding="utf-8").splitlines()) >= int(
            source_line.group("line")
        ):
            return candidate
    raise ValueError("missing local target")


def test_markdown_local_links_and_host_paths_are_valid() -> None:
    problems: list[str] = []
    for document in _markdown_files():
        for number, line in _non_fenced_lines(document):
            if HOST_PATH_RE.search(line):
                problems.append(f"{document.relative_to(ROOT)}:{number}: host-specific path")
            for match in LINK_RE.finditer(line):
                target = match.group("target")
                try:
                    _local_target(target, document)
                except ValueError as exc:
                    problems.append(
                        f"{document.relative_to(ROOT)}:{number}: {exc}: {target}"
                    )
    assert not problems, "\n".join(problems)
