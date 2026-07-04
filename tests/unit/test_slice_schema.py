import json
from importlib.resources import files

import jsonschema
import pytest

SCHEMA = json.loads((files("kolega_security_scanner.schema") / "slice.schema.json").read_text())


def _valid(doc):
    jsonschema.validate(doc, SCHEMA)


def test_terminal_form_valid():
    _valid({"repos": ["realvuln-juice-shop", "realvuln-dvws-node"]})


def test_composition_form_valid():
    _valid({"include": ["human-curated", "js-ts"]})


def test_both_keys_invalid():
    with pytest.raises(jsonschema.ValidationError):
        _valid({"repos": ["realvuln-x"], "include": ["human-curated"]})


def test_neither_key_invalid():
    with pytest.raises(jsonschema.ValidationError):
        _valid({})


def test_empty_repos_invalid():
    with pytest.raises(jsonschema.ValidationError):
        _valid({"repos": []})


def test_duplicate_repos_invalid():
    with pytest.raises(jsonschema.ValidationError):
        _valid({"repos": ["realvuln-x", "realvuln-x"]})
