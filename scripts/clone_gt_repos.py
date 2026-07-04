#!/usr/bin/env python3
"""Clone GT repos at their pinned commits into the git-ignored repos/ drop-zone.

Reads every ground-truth/findings/<repo>/ground-truth.json, and for any repo not
already present under repos/, clones repo_url and checks out commit_sha. Reports
failures (moved/deleted upstreams, missing commits) rather than skipping silently.
Uses git argv form (no shell).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GT = ROOT / "ground-truth" / "findings"
REPOS = ROOT / "repos"


def _git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


def main() -> int:
    REPOS.mkdir(exist_ok=True)
    cloned, skipped, failed = [], [], []
    for gt_file in sorted(GT.glob("*/ground-truth.json")):
        repo_id = gt_file.parent.name
        dest = REPOS / repo_id
        if dest.exists():
            skipped.append(repo_id)
            continue
        data = json.loads(gt_file.read_text())
        url = data.get("repo_url")
        sha = data.get("commit_sha")
        if not url:
            failed.append((repo_id, "no repo_url in GT"))
            continue
        print(f"cloning {repo_id} <- {url}", file=sys.stderr)
        res = _git(["clone", "--quiet", url, str(dest)])
        if res.returncode != 0:
            failed.append((repo_id, f"clone failed: {res.stderr.strip()[:120]}"))
            continue
        if sha:
            co = _git(["checkout", "--quiet", sha], cwd=dest)
            if co.returncode != 0:
                failed.append((repo_id, f"checkout {sha[:10]} failed: {co.stderr.strip()[:120]}"))
                continue
        cloned.append(repo_id)

    print(f"\ncloned={len(cloned)} skipped(existing)={len(skipped)} failed={len(failed)}")
    for repo_id, why in failed:
        print(f"  FAILED {repo_id}: {why}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
