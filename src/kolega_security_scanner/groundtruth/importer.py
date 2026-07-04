"""Import the published RealVulnBenchmark ground-truth into this repo.

Orchestrates: git-repo check, branch/SHA read, clean-worktree check, copy,
in-package validation, slice-manifest generation, and an append-only audit log
entry. All git access uses ``subprocess.run`` argv form (research D-010, no
shell). Slice classification follows data-model.md (authorship and language are
orthogonal — a repo lands in every slice whose rule it satisfies).
"""

from __future__ import annotations

import datetime
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from kolega_security_scanner.cli._errors import GtImportError, UsageError
from kolega_security_scanner.groundtruth.validator import validate_gt_file

_HUMAN = "human-curated"
_VIBE = "vibe-coded-python"
_JS_TS = "js-ts"
_ALL = "all"


@dataclass(frozen=True)
class ImportResult:
    """Summary of a GT import run."""

    branch: str
    sha: str
    repos: int
    validated: int
    failed: int
    failures: tuple[str, ...]
    copied: tuple[str, ...]


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


def _check_is_git_repo(path: Path) -> None:
    if not path.exists():
        raise UsageError(f"--realvuln-path does not exist: {path}")
    res = _git(["rev-parse", "--is-inside-work-tree"], path)
    if res.returncode != 0 or res.stdout.strip() != "true":
        raise UsageError(f"--realvuln-path is not a git repository: {path}")


def read_branch_and_sha(realvuln_path: str | Path) -> tuple[str, str]:
    """Return ``(branch, short_sha)`` for the source repo. Raises UsageError."""
    src = Path(realvuln_path)
    _check_is_git_repo(src)
    branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], src).stdout.strip()
    sha = _git(["rev-parse", "HEAD"], src).stdout.strip()
    return branch, sha[:8]


def _check_clean_worktree(src: Path) -> None:
    porcelain = _git(["status", "--porcelain"], src).stdout.strip()
    if porcelain:
        dirty = "\n".join(f"  {line}" for line in porcelain.splitlines())
        raise GtImportError(f"source worktree is dirty:\n{dirty}")


def _slug(name: str) -> str:
    return name.replace("_", "-").lower()


def _write_slice(slices_dir: Path, name: str, repos: list[str]) -> None:
    body = "".join(f"  - {r}\n" for r in sorted(repos))
    (slices_dir / f"{name}.yaml").write_text(f"repos:\n{body}" if repos else "repos: []\n")


def _write_all_slice(slices_dir: Path, members: list[str]) -> None:
    body = "".join(f"  - {m}\n" for m in members)
    (slices_dir / f"{_ALL}.yaml").write_text(f"include:\n{body}")


def _classify_and_write_manifests(findings_dir: Path, slices_dir: Path) -> None:
    human: list[str] = []
    vibe: list[str] = []
    js_ts: list[str] = []
    for gt in sorted(findings_dir.glob("*/ground-truth.json")):
        repo = _slug(gt.parent.name)
        data = json.loads(gt.read_text())
        authorship = data.get("authorship")
        language = data.get("language")
        if authorship == "human_authored":
            human.append(repo)
        if authorship in {"llm_assisted", "llm_generated"}:
            vibe.append(repo)
        if language in {"javascript", "typescript"}:
            js_ts.append(repo)

    _write_slice(slices_dir, _HUMAN, human)
    _write_slice(slices_dir, _VIBE, vibe)
    _write_slice(slices_dir, _JS_TS, js_ts)
    # all.yaml includes only non-empty terminal slices so it always resolves;
    # an empty js-ts is a tolerated placeholder (slice-schema contract).
    members = [n for n, repos in ((_HUMAN, human), (_VIBE, vibe), (_JS_TS, js_ts)) if repos]
    _write_all_slice(slices_dir, members or [_HUMAN, _VIBE, _JS_TS])


def _append_import_log(log_path: Path, result_fields: dict[str, object]) -> None:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = (
        f"- {ts} | branch={result_fields['branch']} | sha={result_fields['sha']} "
        f"| repos={result_fields['repos']} | validated={result_fields['validated']} "
        f"| failed={result_fields['failed']}\n"
    )
    with log_path.open("a") as fh:
        fh.write(line)


def import_published_gt(
    realvuln_path: str | Path,
    dest_root: str | Path = ".",
    *,
    force: bool = False,
) -> ImportResult:
    """Copy, validate, slice, and log the published GT.

    Raises:
        UsageError: ``--realvuln-path`` is not a git repo (exit 2).
        GtImportError: Dirty source tree, or non-empty target without force
            (exit 1).
    """
    src = Path(realvuln_path)
    branch, sha = read_branch_and_sha(src)
    _check_clean_worktree(src)

    dest = Path(dest_root)
    findings_dir = dest / "ground-truth" / "findings"
    slices_dir = dest / "ground-truth" / "slices"
    findings_dir.mkdir(parents=True, exist_ok=True)
    slices_dir.mkdir(parents=True, exist_ok=True)

    existing = [p for p in findings_dir.iterdir() if p.name != ".gitkeep"]
    if existing and not force:
        raise GtImportError(f"{findings_dir} is not empty; pass --force to overwrite")

    source_gt = src / "ground-truth"
    if not source_gt.is_dir():
        raise GtImportError(f"no ground-truth/ directory under {src}")

    copied: list[str] = []
    failures: list[str] = []
    validated = 0
    for repo_dir in sorted(p for p in source_gt.iterdir() if p.is_dir()):
        target = findings_dir / repo_dir.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(repo_dir, target)
        copied.append(repo_dir.name)
        gt_file = target / "ground-truth.json"
        if gt_file.is_file():
            try:
                validate_gt_file(gt_file)
                validated += 1
            except Exception as exc:  # noqa: BLE001 - report, do not roll back
                failures.append(str(exc))

    _classify_and_write_manifests(findings_dir, slices_dir)

    fields: dict[str, object] = {
        "branch": branch,
        "sha": sha,
        "repos": len(copied),
        "validated": validated,
        "failed": len(failures),
    }
    _append_import_log(dest / "ground-truth" / "IMPORT_LOG.md", fields)

    return ImportResult(
        branch=branch,
        sha=sha,
        repos=len(copied),
        validated=validated,
        failed=len(failures),
        failures=tuple(failures),
        copied=tuple(copied),
    )
