"""Thin adapter over the ``kolega-code`` agentic CLI (ask mode).

The default pipeline pre-stuffs truncated code into a single ``chat_json`` call. The
agentic backend instead hands the task to a ``kolega-code ask`` session that NAVIGATES
the repo (grep/read/list) and returns the phase's structured JSON. We shell out to the
installed CLI with ``--json`` and pull the final ``response`` chunk(s) out of the event
stream, then loosely parse JSON from that text.

Read-only by construction for our purposes: every phase prompt asks only for analysis +
JSON, never edits. Failures (missing binary, missing key, timeout, bad JSON) return
``None`` so callers degrade exactly like a failed ``chat_json``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

# Only deepseek-v4-pro is registered in kolega-code's model table (deepseek provider).
DEFAULT_AGENT_PROVIDER = "deepseek"
DEFAULT_AGENT_MODEL = "deepseek-v4-pro"
_TIMEOUT_S = 3600


def _binary() -> str | None:
    found = shutil.which("kolega-code")
    if found:
        return found
    local = Path.home() / ".local" / "bin" / "kolega-code"
    return str(local) if local.exists() else None


def _extract_response(stdout: str) -> str:
    """Concatenate the ``response`` chunk contents from kolega-code's --json stream."""
    parts: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("kind") == "chunk":
            data = obj.get("data", {})
            if isinstance(data, dict) and data.get("type") == "response":
                parts.append(str(data.get("content", "")))
    return "".join(parts)


def _loads_loose(text: str) -> dict[str, Any] | list[Any] | None:
    """Parse JSON from agent text, tolerating prose/fences around it."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("\n") + 1 :] if "\n" in text else text
    try:
        return cast("dict[str, Any] | list[Any] | None", json.loads(text))
    except json.JSONDecodeError:
        pass
    # Fall back to the outermost {...} or [...] span.
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i, j = text.find(open_c), text.rfind(close_c)
        if 0 <= i < j:
            try:
                return cast("dict[str, Any] | list[Any] | None", json.loads(text[i : j + 1]))
            except json.JSONDecodeError:
                continue
    return None


def run_json(
    prompt: str,
    repo_root: Path | str,
    *,
    provider: str = DEFAULT_AGENT_PROVIDER,
    model: str = DEFAULT_AGENT_MODEL,
    timeout: int = _TIMEOUT_S,
) -> dict[str, Any] | list[Any] | None:
    """Run one ``kolega-code ask`` session over ``repo_root``; return parsed JSON or None.

    The prompt MUST instruct the agent to navigate the repo and reply with strict JSON.
    """
    binary = _binary()
    if binary is None:
        return None
    # kolega-code uses provider-native keys (DEEPSEEK_API_KEY, ANTHROPIC_API_KEY, ...).
    # Load the repo .env so whichever provider's key is needed is present in the subprocess
    # env; if the relevant key is missing kolega-code exits non-zero -> we return None.
    from kolega_security_scanner.llm.client import _load_repo_dotenv

    _load_repo_dotenv()
    # Isolate session state per invocation: kolega-code keeps per-project session state
    # in a shared default dir, so concurrent sessions on the SAME --project collide and
    # return empty. A unique --state-dir per call makes fan-out / batched runs independent.
    import shutil as _shutil
    import tempfile

    state_dir = tempfile.mkdtemp(prefix="kolega_code_state_")
    try:
        proc = subprocess.run(
            [
                binary,
                "ask",
                prompt,
                "--project",
                str(repo_root),
                "--state-dir",
                state_dir,
                "--provider",
                provider,
                "--model",
                model,
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    finally:
        _shutil.rmtree(state_dir, ignore_errors=True)
    _maybe_capture(prompt, proc.returncode, proc.stdout)
    if proc.returncode != 0:
        return None
    return _loads_loose(_extract_response(proc.stdout))


def _maybe_capture(prompt: str, returncode: int, stdout: str) -> None:
    """Persist the raw agent run (prompt + full --json stream) when KA_RAW_TRACE is set."""
    import os
    import tempfile

    base = os.environ.get("KA_RAW_TRACE")
    if not base:
        return
    # Phase label from the prompt's distinctive rubric keywords.
    label = (
        "threat"
        if "threat model" in prompt[:200].lower()
        else (
            "verify"
            if "REPORTED FINDING" in prompt or "verdicts" in prompt
            else ("variant" if "VARIANT HUNT" in prompt else "discovery")
        )
    )
    os.makedirs(base, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=f"{label}_", suffix=".txt", dir=base)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"### PHASE={label} returncode={returncode}\n### PROMPT(head)\n{prompt[:1500]}\n")
        fh.write(f"### RAW STDOUT ({len(stdout)} chars)\n{stdout}")


__all__ = ["run_json", "DEFAULT_AGENT_PROVIDER", "DEFAULT_AGENT_MODEL"]
