from kolega_security_scanner.schema.export import GOLDEN_PATH, dump_finding_schema


def test_committed_schema_matches_generated():
    assert dump_finding_schema() == GOLDEN_PATH.read_text(), (
        "finding.schema.json is stale — regenerate from the Pydantic model"
    )


def test_schema_id_is_pinned():
    import json

    schema = json.loads(GOLDEN_PATH.read_text())
    assert schema["$id"] == "kolega-scan/finding/v1.0.0"
