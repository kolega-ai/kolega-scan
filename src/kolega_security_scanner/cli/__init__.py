"""CLI package for kolega-scan."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from kolega_security_scanner.cli.main import app as app

__all__ = ["app"]


def __getattr__(name: str) -> Any:
    """Lazily re-export ``app`` so importing submodules avoids an import cycle."""
    if name == "app":
        from kolega_security_scanner.cli.main import app

        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
