"""CLI exit codes."""

from __future__ import annotations

EXIT_SUCCESS = 0
EXIT_DOMAIN_FAILURE = 1
EXIT_USAGE_ERROR = 2
EXIT_INTERNAL_ERROR = 10

__all__ = [
    "EXIT_SUCCESS",
    "EXIT_DOMAIN_FAILURE",
    "EXIT_USAGE_ERROR",
    "EXIT_INTERNAL_ERROR",
]
