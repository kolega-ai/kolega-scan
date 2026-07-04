"""Typed error hierarchy for the scanner package."""

from __future__ import annotations


class KolegaScannerError(Exception):
    """Root for every error raised by this package."""


class ValidationError(KolegaScannerError):
    """A domain object failed validation (e.g. a GT file or finding)."""


class UsageError(KolegaScannerError):
    """The caller supplied bad or missing arguments."""


class GtImportError(KolegaScannerError):
    """A ground-truth import operation could not be completed."""


class SliceCycleError(KolegaScannerError):
    """A slice include graph contains a cycle."""


class SliceReferenceError(KolegaScannerError):
    """A slice include references a slice file that does not exist."""


class ScanError(KolegaScannerError):
    """A scan operation could not be completed."""


class DetectorError(KolegaScannerError):
    """A detector misbehaved (e.g. emitted a wrong-cluster finding)."""


class DetectorDiscoveryError(KolegaScannerError):
    """Detector discovery failed (e.g. a duplicate slug)."""


class ProviderDiscoveryError(KolegaScannerError):
    """Scan-provider discovery failed (e.g. a duplicate provider name)."""


class LLMConfigError(KolegaScannerError):
    """An LLM is required but not configured (missing/invalid API key)."""


__all__ = [
    "KolegaScannerError",
    "ValidationError",
    "UsageError",
    "GtImportError",
    "SliceCycleError",
    "SliceReferenceError",
    "ScanError",
    "DetectorError",
    "DetectorDiscoveryError",
    "ProviderDiscoveryError",
    "LLMConfigError",
]
