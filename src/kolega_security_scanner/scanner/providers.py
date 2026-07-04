"""Pluggable whole-scanner providers — the seam for importing scanners from other repos.

A ``ScanProvider`` is a whole-repo scan *strategy*: ``ScanConfig`` in -> ``ScanResult``
out. This sits one level above the per-cluster ``Detector`` seam: a detector finds one
cluster; a provider is an entire scan pipeline (which may run the detector registry, or
a wholly different approach such as a multi-pass LLM pipeline).

The contract is LLM-agnostic: each provider owns its own credential/LLM needs inside
``scan()``. The shipping default is the LLM-driven claude-adaptation pipeline; the
bundled ``"detectors"`` provider runs the cluster-based detector registry through the
engine. Alternative providers ship in separate **installed distributions** and register
under the entry-point group ``kolega_security_scanner.scanners``. This is the
open-sourcing seam: the harness (this package) can be public while a proprietary
scanner — its process, prompts, and detectors — ships in a private distribution that
only registers a provider here. Selected at the CLI with ``--scanner <name>``.

See ``docs/dev/writing-scanners.md`` for the authoring contract.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from kolega_security_scanner.cli._errors import ProviderDiscoveryError, UsageError

log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from kolega_security_scanner.scanner.config import ScanConfig
    from kolega_security_scanner.scanner.models import ScanResult

ENTRY_POINT_GROUP = "kolega_security_scanner.scanners"
# The bundled reference-detector provider; runs the detector registry.
DETECTORS_PROVIDER = "detectors"
# The shipping default: the 2-model (DeepSeek flash+pro) matrix pipeline.
DEFAULT_PROVIDER = "kolega-scan-oss-v1"


@runtime_checkable
class ScanProvider(Protocol):
    """The pluggable whole-scanner contract (structural — external scanners implement it).

    A provider takes a resolved ``ScanConfig`` and returns a ``ScanResult``. The
    contract is LLM-agnostic: whether a scan needs an LLM (and which models/keys it
    uses) is entirely the provider's business. A provider that needs a client builds
    it from the environment inside ``scan()`` and raises ``LLMConfigError`` when its
    credentials are missing — the CLI maps that to a usage error (exit ``2``).
    """

    name: str

    def scan(self, config: ScanConfig) -> ScanResult:
        """Scan the repository named by ``config`` and return its findings."""
        ...


class DetectorScanProvider:
    """The bundled reference provider: run the detector registry through the engine.

    It builds the default detector registry (bundled reference detectors plus any
    entry-point-discovered detectors) and dispatches it via ``scanner.engine.scan``.
    It runs without an LLM: it *opportunistically* builds a client from the environment
    (a missing key means "no LLM", never an error) and LLM-aware detectors simply
    activate when one is present. The one exception is an **explicit** recon request
    (``--recon``): recon needs an LLM, so ``config.recon_explicit`` with no usable
    client raises ``LLMConfigError`` (a usage error at the CLI); the default-on recon
    case degrades silently.
    """

    name = DETECTORS_PROVIDER

    def scan(self, config: ScanConfig) -> ScanResult:
        """Run the bundled + discovered detectors over the repo (unchanged behavior)."""
        # Imported lazily so merely importing this module (e.g. for the Protocol) does
        # not drag in the full engine/detector graph, and to mirror the CLI's pattern.
        import kolega_security_scanner.llm.client as _llm_mod
        from kolega_security_scanner.cli._errors import LLMConfigError
        from kolega_security_scanner.detectors.registry import default_registry
        from kolega_security_scanner.scanner.engine import scan as _engine_scan

        # Opportunistic LLM: LLM-aware detectors (and recon) activate when a key is
        # configured; a missing key just means the deterministic path runs alone.
        llm = None
        try:
            llm = _llm_mod.build_llm_client(config.llm_api_key_env)
        except LLMConfigError:
            llm = None

        if config.recon and config.recon_explicit and llm is None:
            raise LLMConfigError(
                "--recon requires an LLM: configure an API key "
                f"(e.g. ${config.llm_api_key_env}), or omit --recon"
            )

        return _engine_scan(config, default_registry(), llm=llm)


class ProviderRegistry:
    """Holds scan providers, addressable by name; merges entry-point-registered externals."""

    def __init__(self) -> None:
        """Create an empty provider registry."""
        self._by_name: dict[str, ScanProvider] = {}

    def register(self, provider: ScanProvider) -> None:
        """Register a provider; a duplicate name raises ProviderDiscoveryError."""
        if provider.name in self._by_name:
            raise ProviderDiscoveryError(f"duplicate scanner provider: {provider.name}")
        self._by_name[provider.name] = provider

    def all(self) -> list[ScanProvider]:
        """All providers, sorted by name (deterministic)."""
        return [self._by_name[n] for n in sorted(self._by_name)]

    def names(self) -> list[str]:
        """Registered provider names, sorted (deterministic)."""
        return sorted(self._by_name)

    def get(self, name: str) -> ScanProvider:
        """Return the named provider; an unknown name raises UsageError."""
        try:
            return self._by_name[name]
        except KeyError:
            known = ", ".join(self.names()) or "(none)"
            raise UsageError(f"unknown scanner: {name} (known: {known})") from None

    def discover(self, *, include_entry_points: bool = True) -> None:
        """Merge entry-point-registered providers (group ``kolega_security_scanner.scanners``)."""
        if not include_entry_points:
            return
        from importlib.metadata import entry_points

        for ep in entry_points(group=ENTRY_POINT_GROUP):
            try:
                factory = ep.load()
                provider = factory() if callable(factory) else factory
                self.register(cast(ScanProvider, provider))
            except Exception as exc:  # noqa: BLE001 - a bad/duplicate plugin is skipped, never fatal
                log.warning("skipping scanner entry point %s: %s", ep.name, exc)


def default_provider_registry(*, include_entry_points: bool = True) -> ProviderRegistry:
    """A registry with the bundled default provider plus discovered externals."""
    from kolega_security_scanner.scanners.claude_adaptation import (
        build_deepseek_matrix_provider,
        build_kimi_ensemble_provider,
        build_provider,
    )

    reg = ProviderRegistry()
    # The shipping default: the LLM-driven claude-adaptation pipeline (single model).
    reg.register(build_provider())
    # Multi-model variants of claude-adaptation (discovery + verify across models):
    # the DeepSeek flash+pro pair, and the DeepSeek+Kimi ensemble.
    reg.register(build_deepseek_matrix_provider())
    reg.register(build_kimi_ensemble_provider())
    # The bundled reference-detector provider, kept as a selectable scanner that
    # runs the detector registry (no LLM required to run).
    reg.register(DetectorScanProvider())
    # Additional scanners ship as separate installed distributions and register
    # themselves via the entry-point group below.
    reg.discover(include_entry_points=include_entry_points)
    return reg


__all__ = [
    "ENTRY_POINT_GROUP",
    "DEFAULT_PROVIDER",
    "DETECTORS_PROVIDER",
    "ScanProvider",
    "DetectorScanProvider",
    "ProviderRegistry",
    "default_provider_registry",
]
