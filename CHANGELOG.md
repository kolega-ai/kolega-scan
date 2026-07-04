# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
Semantic Versioning from 1.0.0.

## [Unreleased]

Initial public release of the Kolega Scan harness.

### Changed
- Removed the `--mode rules|hybrid` toggle (and the `ScanMode` public export). Whether a
  scan uses an LLM is now decided by the selected scanner and by whether a key is
  configured, not by a CLI flag. The CLI is now fully **LLM-agnostic**: it never builds
  or injects an LLM client, and the `requires_llm` provider attribute is gone. Each
  scanner owns its credentials inside `scan()` — the LLM scanners build their
  own client(s) from the environment and raise `LLMConfigError` (mapped to exit `2`) on
  a missing key; the `detectors` provider builds a client opportunistically (missing key
  = no LLM) and still runs offline. Recon-map building moved behind the provider
  boundary too: an explicit `--recon` with no usable LLM is still a usage error
  (exit `2`), default-on recon still degrades silently. **Breaking:** `--mode` and the
  `mode` YAML key are gone, `ScanMode` is no longer exported, `ScanProvider.scan` is now
  `scan(config) -> ScanResult` (no `llm` parameter), `requires_llm` is removed, and
  `ScanConfig` gains `recon_explicit`.

### Added
- `kolega-scan scan` now streams progress to stderr (phase milestones, per-step
  detail with `-v/--verbose`, elapsed time); `-q/--quiet` limits output to
  warnings. stdout stays clean Finding JSON. Diagnostics use the standard
  `logging` module under the `kolega_security_scanner` logger, so library
  consumers can route or silence them.
- `kolega-scan` CLI: `scan`, `validate-gt`, `import-published-gt`.
- LLM-assisted scanner versions (threat-model -> discovery -> verify -> triage ->
  variant hunt) emitting Semgrep-compatible Finding JSON: `kolega-scan-oss-v1`
  (2-model DeepSeek flash+pro, the default), `kolega-scan-oss-v2` (3-model, adds
  Kimi), and `kolega-scan-oss-ref` (single-model reference pipeline).
- Deterministic reference detectors (`--scanner detectors`, no LLM required).
- Pluggable scanner + detector seams: external providers register at runtime via the
  `kolega_security_scanner.scanners` / `kolega_security_scanner.detectors` entry-point groups.
- Stable public API surface (`PUBLIC_API.md`) with a freeze-guard test.
- Finding + ground-truth + slice JSON schemas; ground-truth validation and slice tooling.

### Fixed
- Public-launch review pass: corrected the GitHub org in all URLs/badges; fixed the
  `--scanner`/`--recon` defaults in `PUBLIC_API.md`; refreshed the credential docs for
  the direct-provider default; and made the offline quickstart runnable with no key.
- CI: the live-LLM lane's secret guard now actually fires; secret scanning runs the
  gitleaks binary (no org-license dependency); mypy/ruff target Python 3.10 to match
  the support floor — which surfaced and fixed a real 3.10 incompatibility
  (`datetime.UTC`).
- Hardening: a scanned repo's `.env` can no longer inject arbitrary environment
  variables (credential-key allowlist only); a broken/duplicate third-party
  scanner/detector plugin is now skipped-with-warning instead of aborting discovery;
  the package version is single-sourced from `__init__.py`.
