# Contributing

## Development setup

```bash
pip install -e ".[dev]"   # or: make setup
make check                # all local gates: lint, format, types, tests
```

Run a single test:

```bash
pytest tests/unit/test_claude_adaptation_variants.py -k kimi
```

## Repository layout

- `src/kolega_security_scanner/` — the package (`scanner` engine, `scanners`, `detectors`,
  `llm`, `schema`, `groundtruth`, `cli`)
- `ground-truth/` — slice manifests (JSON Schemas ship inside the package under
  `schema/`); a ground-truth corpus is imported here, not committed
- `docs/dev/` — design docs

## Evaluation (maintainers)

The scanner is evaluated against a ground-truth corpus that is **imported**, not shipped.
Import it (requires a local checkout of the benchmark), then validate:

```bash
kolega-scan import-published-gt --realvuln-path ../RealVulnBenchmark
kolega-scan validate-gt ground-truth/findings
```

- GT slices: [`docs/dev/gt-slices.md`](docs/dev/gt-slices.md)

## Writing scanners & detectors

- Scanners (whole-repo strategies): [`docs/dev/writing-scanners.md`](docs/dev/writing-scanners.md)
- Detectors (per-cluster): [`docs/dev/writing-detectors.md`](docs/dev/writing-detectors.md)
- LLM scanning: [`docs/dev/llm-scanning.md`](docs/dev/llm-scanning.md)
- Claude-adaptation scanner internals: [`docs/dev/claude-adaptation-scanner.md`](docs/dev/claude-adaptation-scanner.md)

## Public API & versioning

The stable public surface follows SemVer from 1.0.0. Before changing exported symbols,
read [`PUBLIC_API.md`](PUBLIC_API.md) and [`docs/dev/versioning-policy.md`](docs/dev/versioning-policy.md).
