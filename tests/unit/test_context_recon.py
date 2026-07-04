"""US3 — DetectorContext carries the recon map. T017."""

from __future__ import annotations

import dataclasses

import pytest

from kolega_security_scanner.scanner.models import DetectorContext
from kolega_security_scanner.scanner.recon import ReconResult


def test_context_recon_defaults_none() -> None:
    ctx = DetectorContext()
    assert ctx.recon is None


def test_context_carries_recon_and_is_frozen() -> None:
    recon = ReconResult(repo="r")
    ctx = DetectorContext(llm=None, recon=recon)
    assert ctx.recon is recon
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.recon = None  # type: ignore[misc]
