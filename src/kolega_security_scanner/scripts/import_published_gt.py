"""``python -m`` wrapper around the GT importer CLI command."""

from __future__ import annotations

import sys

from kolega_security_scanner.cli.main import app


def main() -> None:
    """Invoke ``kolega-scan import-published-gt`` with passed-through args."""
    app(args=["import-published-gt", *sys.argv[1:]])


if __name__ == "__main__":
    main()
