"""Output schema for the scanner: the Semgrep-JSON-compatible Finding model."""

from kolega_security_scanner.schema.finding import (
    Finding,
    FindingExtra,
    FindingMetadata,
    FindingMetadataKolega,
    StartOrEnd,
)

__all__ = [
    "Finding",
    "FindingExtra",
    "FindingMetadata",
    "FindingMetadataKolega",
    "StartOrEnd",
]
