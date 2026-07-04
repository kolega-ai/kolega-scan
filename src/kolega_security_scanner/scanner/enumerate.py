"""Source-file enumeration for a scan target."""

from __future__ import annotations

from pathlib import Path

from kolega_security_scanner.scanner.models import ScanTarget, SourceFile

SOURCE_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
}
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".hypothesis",
    ".tox",
}
MAX_BYTES = 1_000_000
# Lines longer than this signal a minified/bundled/generated file (real source
# rarely exceeds a few hundred chars). Such files are vendored third-party assets,
# not application code, and their multi-kilobyte single lines trigger catastrophic
# regex backtracking (ReDoS) in detectors. Skip them.
MAX_LINE_BYTES = 5_000


def _is_binary(path: Path) -> bool:
    try:
        return b"\x00" in path.read_bytes()[:1024]
    except OSError:  # pragma: no cover
        return True


def _is_minified(path: Path) -> bool:
    """Return True if any line exceeds MAX_LINE_BYTES (minified/bundled file)."""
    try:
        with path.open("rb") as fh:
            return any(len(line) > MAX_LINE_BYTES for line in fh)
    except OSError:  # pragma: no cover
        return True


def enumerate_sources(repo_root: str | Path, *, skip_minified: bool = True) -> ScanTarget:
    """Return a ScanTarget of recognized source files (skipping vendor/binary).

    ``skip_minified`` drops files with very long lines (minified/bundled assets) to
    protect regex detectors from ReDoS. LLM-only scanners run no regex over the source,
    so they pass ``skip_minified=False`` to keep dense single-file apps (e.g. dsvw.py)
    that would otherwise be excluded.
    """
    root = Path(repo_root)
    files: list[SourceFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if SKIP_DIRS.intersection(rel.parts):
            continue
        language = SOURCE_EXT.get(path.suffix)
        if language is None:
            continue
        if path.stat().st_size > MAX_BYTES or _is_binary(path):
            continue
        if skip_minified and _is_minified(path):
            continue
        files.append(SourceFile(path=rel.as_posix(), language=language))
    return ScanTarget(repo_root=root, files=tuple(files))
