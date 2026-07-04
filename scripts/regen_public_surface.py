#!/usr/bin/env python3
"""Regenerate the committed public-API surface snapshot (intentional surface changes)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kolega_security_scanner._public_surface import SNAPSHOT_PATH, dump_surface  # noqa: E402

if __name__ == "__main__":
    SNAPSHOT_PATH.write_text(dump_surface())
    print(f"wrote {SNAPSHOT_PATH}")
