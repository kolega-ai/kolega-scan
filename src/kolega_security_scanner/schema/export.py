"""Deterministic JSON Schema export for the Finding model.

Both the committed golden file and the golden-fixture test call
:func:`dump_finding_schema` so their byte streams are identical by construction.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kolega_security_scanner.schema.finding import Finding

FINDING_SCHEMA_ID = "kolega-scan/finding/v1.0.0"
JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"

GOLDEN_PATH = Path(__file__).with_name("finding.schema.json")


def build_finding_schema() -> dict[str, Any]:
    """Return the Finding JSON Schema with a pinned ``$id`` and dialect."""
    schema = Finding.model_json_schema(mode="serialization")
    schema["$id"] = FINDING_SCHEMA_ID
    schema["$schema"] = JSON_SCHEMA_DIALECT
    return schema


def dump_finding_schema() -> str:
    """Serialize the Finding schema deterministically (sorted keys, 2-space)."""
    return json.dumps(build_finding_schema(), indent=2, sort_keys=True) + "\n"
