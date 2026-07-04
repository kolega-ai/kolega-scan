"""Introspect the package public surface for the freeze guard (deterministic).

Builds a sorted dict of the public Python symbols (+ kinds/signatures), CLI commands
and their parameters, exit codes, the detector entry-point group, and the committed
schema ``$id``s. Compared against a committed golden by the guard test.
"""

from __future__ import annotations

import inspect
import json
from importlib import import_module
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]

PUBLIC_MODULES = (
    "kolega_security_scanner.schema.finding",
    "kolega_security_scanner.groundtruth.validator",
    "kolega_security_scanner.groundtruth.slices",
    "kolega_security_scanner.scanner.engine",
    "kolega_security_scanner.scanner.config",
    "kolega_security_scanner.scanner.models",
    "kolega_security_scanner.scanner.providers",
    "kolega_security_scanner.detectors.base",
    "kolega_security_scanner.detectors.registry",
    "kolega_security_scanner.llm.client",
    "kolega_security_scanner.cli._errors",
    "kolega_security_scanner.cli._exit_codes",
)


def _describe(obj: Any) -> str:
    if inspect.isclass(obj):
        return "class"
    if callable(obj):
        try:
            return "def" + str(inspect.signature(obj))
        except (TypeError, ValueError):
            return "callable"
    return "value"


def _module_symbols(module_name: str) -> dict[str, str]:
    mod = import_module(module_name)
    names = sorted(getattr(mod, "__all__", []))
    return {n: _describe(getattr(mod, n)) for n in names}


def build_surface() -> dict[str, Any]:
    """Return a deterministic dict describing the public surface."""
    import kolega_security_scanner as pkg
    from kolega_security_scanner.cli import _exit_codes as ec
    from kolega_security_scanner.cli.main import app
    from kolega_security_scanner.detectors.registry import ENTRY_POINT_GROUP
    from kolega_security_scanner.scanner.providers import (
        ENTRY_POINT_GROUP as SCANNER_ENTRY_POINT_GROUP,
    )

    python: dict[str, dict[str, str]] = {
        "kolega_security_scanner": {
            n: _describe(getattr(pkg, n)) for n in sorted(pkg.__all__) if n != "__version__"
        }
    }
    for m in PUBLIC_MODULES:
        python[m] = _module_symbols(m)

    cli: dict[str, list[str]] = {}
    for cmd in app.registered_commands:
        if cmd.name and cmd.callback is not None:
            cli[cmd.name] = sorted(inspect.signature(cmd.callback).parameters)

    exit_codes = {n: getattr(ec, n) for n in sorted(ec.__all__)}

    # Load packaged schemas via importlib.resources so this resolves from an
    # installed wheel (not just the source tree).
    from importlib.resources import files as _pkg_files

    schema_ids = []
    for entry in _pkg_files("kolega_security_scanner.schema").iterdir():
        if not entry.name.endswith(".schema.json"):
            continue
        try:
            sid = json.loads(entry.read_text()).get("$id")
            if sid:
                schema_ids.append(sid)
        except (OSError, json.JSONDecodeError):
            continue

    return {
        "package_version": pkg.__version__,
        "python": {k: dict(sorted(v.items())) for k, v in sorted(python.items())},
        "cli": dict(sorted(cli.items())),
        "exit_codes": exit_codes,
        "entry_point_group": ENTRY_POINT_GROUP,
        "scanner_entry_point_group": SCANNER_ENTRY_POINT_GROUP,
        "schema_ids": sorted(schema_ids),
    }


SNAPSHOT_PATH = Path(__file__).with_name("schema") / "public_api.snapshot.json"


def dump_surface() -> str:
    """Serialize the surface deterministically (sorted keys, 2-space)."""
    return json.dumps(build_surface(), indent=2, sort_keys=True) + "\n"
