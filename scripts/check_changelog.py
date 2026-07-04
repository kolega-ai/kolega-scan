#!/usr/bin/env python3
"""Enforce a CHANGELOG [Unreleased] bullet when user-visible files are staged.

User-visible = any path under src/ or docs/, OR any *.schema.json / slice *.yaml
anywhere. Changes confined to tests/, repos/, or ground-truth/findings/ do not
require a CHANGELOG entry.

Exit 0 when satisfied or not applicable; exit 1 when a bullet is required but
the [Unreleased] section is empty.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHANGELOG = REPO / "CHANGELOG.md"

USER_VISIBLE_DIRS = ("src/", "docs/")
NON_VISIBLE_DIRS = (
    "tests/",
    "repos/",
    "ground-truth/findings/",
)


def _staged_files() -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def _is_user_visible(path: str) -> bool:
    if any(path.startswith(d) for d in NON_VISIBLE_DIRS):
        return False
    if any(path.startswith(d) for d in USER_VISIBLE_DIRS):
        return True
    if path.endswith(".schema.json"):
        return True
    if path.endswith(".yaml") and "slices" in path:
        return True
    return False


def _unreleased_has_bullet() -> bool:
    if not CHANGELOG.exists():
        return False
    lines = CHANGELOG.read_text().splitlines()
    in_unreleased = False
    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith("## [unreleased]"):
            in_unreleased = True
            continue
        if in_unreleased and stripped.startswith("## "):
            break
        if in_unreleased and stripped.startswith(("-", "*")):
            return True
    return False


def main() -> int:
    visible = [p for p in _staged_files() if _is_user_visible(p)]
    if not visible:
        return 0
    if _unreleased_has_bullet():
        return 0
    print(
        "CHANGELOG.md [Unreleased] needs a bullet — user-visible files staged:",
        file=sys.stderr,
    )
    for p in visible:
        print(f"  {p}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
