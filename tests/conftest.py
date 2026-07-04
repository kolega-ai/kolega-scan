"""Shared pytest fixtures."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


#: Every env var an LLM client factory may read a credential/backend from.
LLM_ENV_VARS = (
    "DEEPSEEK_API_KEY",
    "MOONSHOT_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "LITELLM_API_KEY",
    "LITELLM_URL",
    "LITELLM_BASE_URL",
    "KOLEGA_LLM_BACKEND",
)


@pytest.fixture
def no_llm_env(monkeypatch, tmp_path):
    """Guarantee no LLM client can be built: scrub key env vars AND prevent .env pickup.

    Chdirs to tmp_path so a developer machine's CWD .env cannot re-supply keys —
    missing-key tests stay hermetic even on machines with keys configured.
    """
    for var in LLM_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def run_cli():
    def _run(args, cwd=None, stdin=None):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(SRC)
        return subprocess.run(
            [sys.executable, "-m", "kolega_security_scanner.cli.main", *args],
            cwd=str(cwd or REPO_ROOT),
            capture_output=True,
            text=True,
            input=stdin,
            env=env,
            check=False,
        )

    return _run


def _git_init_commit(path: Path) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    subprocess.run(["git", "init", "-q"], cwd=path, check=True, env=env)
    subprocess.run(["git", "add", "-A"], cwd=path, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "seed"], cwd=path, check=True, env=env)


@pytest.fixture
def gt_source_repo(tmp_path) -> Path:
    """A clean git repo whose ground-truth/ mirrors the valid fixtures."""
    src = tmp_path / "RealVulnBenchmark"
    shutil.copytree(FIXTURES / "realvuln-mirror" / "ground-truth", src / "ground-truth")
    _git_init_commit(src)
    return src


@pytest.fixture
def scanner_dest(tmp_path) -> Path:
    """An empty scanner repo layout (ground-truth/findings + slices + log)."""
    dest = tmp_path / "scanner"
    (dest / "ground-truth" / "findings").mkdir(parents=True)
    (dest / "ground-truth" / "slices").mkdir(parents=True)
    (dest / "ground-truth" / "IMPORT_LOG.md").write_text("<!-- log -->\n")
    return dest
