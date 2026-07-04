"""Kolega Scan — LLM-assisted SAST package and CLI.

This module is the public API facade. Everything in ``__all__`` is the stable public
surface (see PUBLIC_API.md). Anything not exported here is internal.
"""

from __future__ import annotations

import logging

from kolega_security_scanner.cli._errors import (
    DetectorDiscoveryError,
    DetectorError,
    GtImportError,
    KolegaScannerError,
    LLMConfigError,
    ProviderDiscoveryError,
    ScanError,
    SliceCycleError,
    SliceReferenceError,
    UsageError,
    ValidationError,
)
from kolega_security_scanner.cli._exit_codes import (
    EXIT_DOMAIN_FAILURE,
    EXIT_INTERNAL_ERROR,
    EXIT_SUCCESS,
    EXIT_USAGE_ERROR,
)
from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass, Detector
from kolega_security_scanner.detectors.registry import DetectorRegistry, default_registry
from kolega_security_scanner.groundtruth.slices import resolve_slice
from kolega_security_scanner.groundtruth.validator import validate_gt_dir, validate_gt_file
from kolega_security_scanner.llm.client import AgentResult, LLMClient  # provisional
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.engine import scan
from kolega_security_scanner.scanner.models import (
    DetectorContext,
    ScanResult,
    ScanTarget,
)
from kolega_security_scanner.scanner.providers import (
    ProviderRegistry,
    ScanProvider,
    default_provider_registry,
)
from kolega_security_scanner.scanner.recon import (
    EndpointRecon,
    ReconResult,
    build_recon,
)
from kolega_security_scanner.schema.finding import (
    Finding,
    FindingExtra,
    FindingMetadata,
    FindingMetadataKolega,
    StartOrEnd,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # output schema
    "Finding",
    "FindingExtra",
    "FindingMetadata",
    "FindingMetadataKolega",
    "StartOrEnd",
    # ground truth
    "validate_gt_file",
    "validate_gt_dir",
    "resolve_slice",
    # scanner
    "scan",
    "ScanConfig",
    "ScanResult",
    "ScanTarget",
    "DetectorContext",
    # scan providers (pluggable whole-scanner seam)
    "ScanProvider",
    "ProviderRegistry",
    "default_provider_registry",
    # recon (shared LLM-backed threat-model map)
    "ReconResult",
    "EndpointRecon",
    "build_recon",
    # detector extension contract
    "Detector",
    "BaseDetector",
    "DetectionClass",
    "DetectorRegistry",
    "default_registry",
    # LLM (provisional)
    "LLMClient",
    "AgentResult",
    # errors
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
    # exit codes
    "EXIT_SUCCESS",
    "EXIT_DOMAIN_FAILURE",
    "EXIT_USAGE_ERROR",
    "EXIT_INTERNAL_ERROR",
]

# Library best practice: attach a no-op handler so importing the package never
# emits logs on its own. Applications (the CLI, or a downstream consumer) opt in
# by configuring a handler on the ``kolega_security_scanner`` logger.
logging.getLogger("kolega_security_scanner").addHandler(logging.NullHandler())
