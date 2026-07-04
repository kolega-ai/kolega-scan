from kolega_security_scanner._public_surface import SNAPSHOT_PATH, dump_surface


def test_public_surface_matches_committed_snapshot():
    assert dump_surface() == SNAPSHOT_PATH.read_text(), (
        "Public API surface changed. If intentional, run "
        "`python scripts/regen_public_surface.py` and commit the snapshot diff."
    )
