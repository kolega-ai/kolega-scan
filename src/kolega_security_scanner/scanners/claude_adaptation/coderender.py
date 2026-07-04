"""Render source code into line-numbered blocks for prompts (shared by phases).

Line numbering is essential: discovery cites a 1-based line and the verifier needs the
surrounding context. Budgets (per-file / per-prompt char caps) keep token usage bounded.
"""

from __future__ import annotations

from kolega_security_scanner.scanner.models import ScanTarget


def number_lines(text: str, *, start: int = 1, max_chars: int | None = None) -> str:
    """Prefix each line with its 1-based number (``  12| code``), optionally truncated."""
    if max_chars is not None and len(text) > max_chars:
        text = text[:max_chars] + "\n...(truncated)"
    out = []
    for i, line in enumerate(text.splitlines(), start=start):
        out.append(f"{i:>5}| {line}")
    return "\n".join(out)


def render_file_block(target: ScanTarget, rel_path: str, *, max_chars: int) -> str:
    """Render one repo file as a header + line-numbered body (truncated to budget)."""
    try:
        text = target.read_text(rel_path)
    except OSError:
        return ""
    body = number_lines(text, max_chars=max_chars)
    return f"### FILE: {rel_path}\n{body}"


def render_partition(
    target: ScanTarget,
    files: tuple[str, ...],
    *,
    max_chars_per_file: int,
    max_chars_per_prompt: int,
) -> str:
    """Concatenate line-numbered file blocks until the per-prompt budget is hit."""
    blocks: list[str] = []
    used = 0
    for rel in files:
        block = render_file_block(target, rel, max_chars=max_chars_per_file)
        if not block:
            continue
        if used + len(block) > max_chars_per_prompt and blocks:
            break
        blocks.append(block)
        used += len(block)
    return "\n\n".join(blocks)


def context_window(text: str, line: int, *, radius: int) -> str:
    """Return a line-numbered window of ``text`` centered on ``line`` (1-based)."""
    lines = text.splitlines()
    lo = max(0, line - 1 - radius)
    hi = min(len(lines), line + radius)
    window = "\n".join(lines[lo:hi])
    return number_lines(window, start=lo + 1)


__all__ = [
    "number_lines",
    "render_file_block",
    "render_partition",
    "context_window",
]
