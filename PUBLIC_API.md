# Public API (pre-1.0 — stabilizing toward v1.0.0)

This is the authoritative public surface of `kolega-scan`. While pre-1.0 it
may still change; full SemVer guarantees begin at 1.0.0 (rules in
[`docs/dev/versioning-policy.md`](docs/dev/versioning-policy.md)). A committed snapshot
(`src/kolega_security_scanner/schema/public_api.snapshot.json`) plus
`tests/unit/test_public_surface_guard.py` fail CI on accidental drift.

**Anything not listed here is internal and may change without notice.**
Stability tiers: **stable** (full SemVer guarantee) · **provisional** (may change in a
MINOR release until promoted).

## 1. Output schemas — stable
JSON Schemas, each `$id`'d and golden-tested:
- Finding — `kolega-scan/finding/v1.0.0`
- Ground-truth, Slice.

## 2. Detector extension contract — stable
- `Detector` Protocol + `BaseDetector` ABC: `slug`, `cluster_id`, `languages`,
  `detection_class`, `needs_recon` (bool, default `False`),
  `run(target, ctx) -> Iterable[Finding]`. A detector that sets `needs_recon = True`
  receives the shared recon map via `ctx.recon` when the engine built one.
- Entry-point group: **`kolega_security_scanner.detectors`** (external detector
  distributions register here).

### Scan-provider extension contract — stable
- `ScanProvider` Protocol + `ProviderRegistry` + `default_provider_registry()`: a
  *whole-scanner* seam one level above detectors — `name: str` and
  `scan(config) -> ScanResult`. The contract is **LLM-agnostic**: a provider that needs
  an LLM builds its own client(s) inside `scan()` and raises `LLMConfigError` when its
  credentials are missing (mapped to exit `2` by the CLI). Use it to ship an entire
  alternative scan pipeline (e.g. a multi-pass LLM scanner). Bundled: the
  Kolega Scan OSS versions (`kolega-scan-oss-v1` default, `kolega-scan-oss-v2`,
  `kolega-scan-oss-ref`) and `detectors` (runs the detector registry
  through the engine).
- Entry-point group: **`kolega_security_scanner.scanners`** (external scanner
  distributions register here; selected with `--scanner`). This is the open-sourcing
  seam: a public harness + a private scanner distribution.

## 3. CLI contract — stable
- Commands: `scan`, `validate-gt`, `import-published-gt` (+ documented flags).
- `scan --scanner <name>` (**default `kolega-scan-oss-v1`**, the 2-model LLM
  find-and-fix pipeline): picks the scanner; each scanner documents its own credential needs (the
  CLI builds no LLM client). `detectors` runs the bundled reference-detector registry
  (no key required). An unknown name is a usage error (exit `2`); a scanner whose
  credentials are missing is likewise a usage error (exit `2`).
- `scan --recon/--no-recon` (**default on**): scan configuration threaded to the scanner
  via `ScanConfig`. The `detectors` scanner builds the LLM-backed per-repo recon map and
  feeds it to recon-aware detectors when an LLM is available; silently skipped when one
  is not (so a no-LLM run is unaffected). An **explicit** `--recon` without an LLM is a
  usage error (exit `2`). Also settable via YAML `recon` (explicit flag wins).
- `scan --verbose/-v` (DEBUG progress), `scan --quiet/-q` (warnings only).
- Exit codes: `0` success · `1` domain failure · `2` usage error · `10` internal.
- stdout = deterministic machine output; stderr = human messages.

## 4. Importable Python API
Import from the top-level facade: `from kolega_security_scanner import ...`

**Stable:**
`__version__`, `Finding`, `FindingExtra`, `FindingMetadata`, `FindingMetadataKolega`,
`StartOrEnd`, `validate_gt_file`, `validate_gt_dir`,
`resolve_slice`, `scan`, `ScanConfig`,
`ScanResult`, `ScanTarget`, `DetectorContext` (incl. the optional `recon` field),
`ReconResult`, `EndpointRecon`, `build_recon`, `Detector`, `BaseDetector`,
`DetectionClass`, `DetectorRegistry`, `default_registry`, `ScanProvider`,
`ProviderRegistry`, `default_provider_registry`, and the error hierarchy
(`KolegaScannerError`, `ValidationError`, `UsageError`, `GtImportError`, `SliceCycleError`,
`SliceReferenceError`, `ScanError`, `DetectorError`, `DetectorDiscoveryError`,
`ProviderDiscoveryError`, `LLMConfigError`) + exit-code
constants (`EXIT_SUCCESS`, `EXIT_DOMAIN_FAILURE`, `EXIT_USAGE_ERROR`, `EXIT_INTERNAL_ERROR`).

**Provisional:** `LLMClient` (now incl. `chat`/`chat_json`/`preflight` for LiteLLM-backed LLM-assisted scanning), `AgentResult` (LLM interface — may change in MINOR).

## 5. Cluster label — stable convention
`cluster_id` (`^[a-z][a-z0-9_]+$`) is the stable key coupling a Finding to the
Detector that produced it. Each detector declares its own `cluster_id`; the harness
ships no fixed cluster set, so the specific labels a distribution uses are its own
concern and are **not** part of this surface.
