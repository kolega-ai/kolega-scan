# Writing Scan Providers

A **scan provider** is a whole-repo scan *strategy*: `ScanConfig` in → `ScanResult` out.
It sits one level above the [detector](./writing-detectors.md) seam — a *detector* finds
one cluster; a *provider* is an entire scan pipeline. Reach for a provider when your
scanner is not a set of per-cluster detectors: e.g. a multi-pass LLM pipeline that emits
findings across many clusters from a single pass, a wrapper around a third-party engine,
or any wholly different approach you want to select at runtime.

## Interface

```python
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.models import ScanResult


class MyScanner:
    name = "my-scanner"            # unique; selected with `--scanner my-scanner`

    def scan(self, config: ScanConfig) -> ScanResult:
        # config.repo_path, config.clusters, config.detectors, config.recon
        # Build and return a ScanResult(repo_dir=..., findings=[Finding, ...]).
        ...
```

`ScanProvider` is a structural `Protocol` — you do not import or subclass anything; any
object with a `name: str` attribute and a matching `scan(...)` method qualifies.

Rules:

- `name` must be unique across all registered providers (a duplicate raises
  `ProviderDiscoveryError`). Do not reuse the bundled names (`kolega-scan-oss-v1`, `kolega-scan-oss-v2`, `kolega-scan-oss-ref`, `detectors`).
- Return a `ScanResult`; its `repo_dir` keys the output JSON and `findings` are emitted as
  the same Semgrep-compatible Finding wire format as the detector path.
- The contract is **LLM-agnostic**: the CLI never builds or injects an LLM client. If
  your scanner needs one, build it yourself inside `scan()` from the environment (see
  `kolega_security_scanner.llm.client.build_llm_client` /
  `build_llm_client_for_model`) and raise `LLMConfigError` when your credentials are
  missing — the CLI maps that to a usage error (exit `2`). Document your scanner's
  credential needs; an LLM-optional scanner should treat a missing key as "run without
  an LLM" (that is what the bundled `detectors` provider does).
- Never raise for a routine "no findings" — return an empty `ScanResult`. A provider that
  raises during discovery is reported to stderr and skipped (never fatal).

## Registration

**External distribution** — add to your package's `pyproject.toml`:

```toml
[project.entry-points."kolega_security_scanner.scanners"]
my-scanner = "my_pkg.scanner:MyScanner"
```

The entry point may load to a provider instance, or to a zero-arg factory/class that
returns one. The harness discovers it automatically; run it with:

```bash
kolega-scan scan ./repo --scanner my-scanner --out out.json
```

This is the **open-sourcing seam**: the harness — engine, CLI, and the bundled
reference detectors — can be public, while a proprietary scanner (its process, prompts,
and detectors) ships in a separate private distribution that registers a provider here.
Only an environment with that distribution installed can select it; everywhere else,
`--scanner` resolves only the providers that are present (`detectors` always is).

**Bundled providers** — the claude-adaptation LLM pipeline (the shipping default) and
`DetectorScanProvider` (`name = "detectors"`, the internal dev example) are registered
in-process by `scanner/providers.py:default_provider_registry()`. `detectors` runs the
cluster detector registry through `scanner.engine.scan`; it builds an LLM client
*opportunistically* (missing key = no LLM, never an error) so LLM-aware detectors and
the recon map activate only when credentials are configured. An explicit `--recon`
(`config.recon_explicit`) with no usable LLM raises `LLMConfigError`.

## Provider vs. detector — which seam?

- **Detector** (group `kolega_security_scanner.detectors`): you find **one cluster** and
  emit findings only for it. The engine runs you alongside all other detectors, builds
  the shared recon map once, isolates your crashes, and dedupes/sorts the output. Prefer
  this for a normal rule / flow / single-cluster LLM check. See
  [writing-detectors.md](./writing-detectors.md).
- **Provider** (group `kolega_security_scanner.scanners`): you own the **entire scan** for
  the repo and return the whole `ScanResult`. Prefer this for a different pipeline
  (multi-pass LLM, third-party engine wrapper, cross-cluster analysis).

A provider can, of course, build and run its own `DetectorRegistry` internally — that is
exactly what the bundled `detectors` provider does.
