"""Pydantic v2 models for the scanner output contract (Finding).

The wire format is Semgrep-JSON-compatible so any Semgrep-aware consumer can
read scanner output without translation. Kolega-specific extensions live under
``extra.metadata.kolega.*``. Models are frozen and forbid extra fields to catch
producer-side schema drift.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]

CWE_PATTERN = r"^CWE-\d+$"
# Generic detector-slug format. A detector reports whatever slug it likes; the
# schema only constrains the shape, not any particular catalog of slugs.
DETECTOR_SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]*$"

_FROZEN = ConfigDict(frozen=True, extra="forbid")


class StartOrEnd(BaseModel):
    """A source position: 1-based line and optional 1-based column."""

    model_config = _FROZEN

    line: int = Field(ge=1)
    col: int | None = Field(default=None, ge=1)


class FindingMetadataKolega(BaseModel):
    """Kolega-specific finding metadata. Every sub-field is optional."""

    model_config = _FROZEN

    cluster_id: str | None = None
    root_key: str | None = None
    detector_slug: Annotated[str, Field(pattern=DETECTOR_SLUG_PATTERN)] | None = None
    confidence: Confidence | None = None


class FindingMetadata(BaseModel):
    """Finding metadata: required CWE list plus optional Kolega extension."""

    model_config = _FROZEN

    cwe: list[Annotated[str, Field(pattern=CWE_PATTERN)]] = Field(min_length=1)
    kolega: FindingMetadataKolega | None = None


class FindingExtra(BaseModel):
    """The Semgrep ``extra`` envelope: message, severity, metadata."""

    model_config = _FROZEN

    message: str = Field(min_length=1)
    severity: Severity
    metadata: FindingMetadata


class Finding(BaseModel):
    """A single scanner finding in Semgrep-JSON-compatible wire format."""

    model_config = _FROZEN

    path: str = Field(min_length=1)
    check_id: str = Field(min_length=1)
    start: StartOrEnd
    end: StartOrEnd | None = None
    extra: FindingExtra

    @field_validator("path")
    @classmethod
    def _path_is_relative_forward_slash(cls, value: str) -> str:
        if value.startswith("/"):
            raise ValueError("path must be relative (no leading '/')")
        if "\\" in value:
            raise ValueError("path must use forward slashes")
        if ".." in value.split("/"):
            raise ValueError("path must not contain '..' segments")
        return value

    @model_validator(mode="after")
    def _end_after_start(self) -> Finding:
        if self.end is not None and self.end.line < self.start.line:
            raise ValueError("end.line must be >= start.line")
        return self
