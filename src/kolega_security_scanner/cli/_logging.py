"""Console logging setup for the CLI.

Progress/diagnostics go to **stderr** (stdout stays clean, machine-readable JSON).
The library itself only ever logs to the ``kolega_security_scanner`` logger and
attaches a ``NullHandler``; this module is where the CLI opts in to real output.
"""

from __future__ import annotations

import logging
import sys
import time

_ROOT = "kolega_security_scanner"


class _ElapsedFormatter(logging.Formatter):
    """Prefix each line with whole seconds elapsed since configuration."""

    def __init__(self) -> None:
        super().__init__("%(message)s")
        self._start = time.monotonic()

    def format(self, record: logging.LogRecord) -> str:
        elapsed = int(time.monotonic() - self._start)
        return f"[{elapsed:>4}s] {record.getMessage()}"


def configure_logging(verbosity: int = 0) -> None:
    """Install a single stderr handler on the package logger.

    ``verbosity``: ``0`` = INFO (default), ``< 0`` = WARNING (quiet),
    ``> 0`` = DEBUG (verbose). Idempotent — safe to call more than once.
    """
    level = logging.INFO
    if verbosity < 0:
        level = logging.WARNING
    elif verbosity > 0:
        level = logging.DEBUG

    logger = logging.getLogger(_ROOT)
    logger.setLevel(level)
    logger.propagate = False

    for h in logger.handlers:
        if getattr(h, "_kolega_console", False):
            h.setLevel(level)
            return

    handler = logging.StreamHandler(sys.stderr)
    handler._kolega_console = True  # type: ignore[attr-defined]
    handler.setLevel(level)
    handler.setFormatter(_ElapsedFormatter())
    logger.addHandler(handler)
