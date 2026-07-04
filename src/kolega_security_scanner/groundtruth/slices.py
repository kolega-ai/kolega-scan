"""Slice manifest schema validation and recursive resolution.

A slice is a named subset of GT repos. Terminal slices list ``repos``;
composition slices ``include`` other slices. Resolution flattens includes,
deduplicates, sorts (deterministic output), and detects
cycles and dangling references.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import yaml

from kolega_security_scanner.cli._errors import (
    SliceCycleError,
    SliceReferenceError,
    ValidationError,
)


def _load_schema() -> dict[str, object]:
    # Packaged alongside the code so it resolves from an installed wheel.
    from importlib.resources import files

    text = (files("kolega_security_scanner.schema") / "slice.schema.json").read_text()
    schema: dict[str, object] = json.loads(text)
    return schema


def _load_slice_file(name: str, slices_dir: Path) -> dict[str, object]:
    path = slices_dir / f"{name}.yaml"
    if not path.is_file():
        raise SliceReferenceError(f"slice not found: {name} ({path})")
    import jsonschema

    data = yaml.safe_load(path.read_text())
    try:
        jsonschema.validate(data, _load_schema())
    except jsonschema.ValidationError as exc:
        raise ValidationError(f"slice {name} invalid: {exc.message}") from exc
    if not isinstance(data, dict):  # pragma: no cover - schema guarantees object
        raise ValidationError(f"slice {name} must be a mapping")
    return data


def resolve_slice(name: str, slices_dir: str | Path) -> list[str]:
    """Return the sorted, deduplicated repo list for the named slice.

    Args:
        name: Slice name (filename without ``.yaml``).
        slices_dir: Directory holding slice manifests.

    Returns:
        Sorted unique repo names.

    Raises:
        SliceReferenceError: An include references a non-existent slice.
        SliceCycleError: The include graph contains a cycle.
        ValidationError: A slice file fails schema validation.
    """
    root = Path(slices_dir)
    repos: set[str] = set()

    def visit(slice_name: str, stack: tuple[str, ...]) -> None:
        if slice_name in stack:
            cycle = " -> ".join((*stack, slice_name))
            raise SliceCycleError(f"slice include cycle: {cycle}")
        data = _load_slice_file(slice_name, root)
        terminal = data.get("repos")
        if terminal is not None:
            repos.update(cast("list[str]", terminal))
            return
        for child in cast("list[str]", data["include"]):
            visit(child, (*stack, slice_name))

    visit(name, ())
    return sorted(repos)
