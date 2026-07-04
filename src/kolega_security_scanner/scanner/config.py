"""Scan configuration (the params-in side of the contract)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScanConfig:
    """All inputs to a scan run.

    There is no deterministic/LLM toggle here: whether a scan uses an LLM is
    decided by the selected scanner/detectors and by whether a client is
    available, not by a mode flag.

    ``recon`` is on by default but degrades silently when no LLM is available;
    ``recon_explicit`` records that the user *demanded* recon (typed ``--recon``),
    which providers treat as an error when no LLM can be built.
    """

    repo_path: Path
    clusters: tuple[str, ...] | None = None
    detectors: tuple[str, ...] | None = None
    out: Path | None = None
    llm_api_key_env: str = "LITELLM_API_KEY"
    recon: bool = True
    recon_explicit: bool = False


__all__ = [
    "ScanConfig",
]
