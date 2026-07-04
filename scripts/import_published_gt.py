#!/usr/bin/env python3
"""Thin wrapper: run the GT importer without requiring an editable install.

Adds ../src to sys.path then delegates to the package module entry point.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kolega_security_scanner.scripts.import_published_gt import main  # noqa: E402

if __name__ == "__main__":
    main()
