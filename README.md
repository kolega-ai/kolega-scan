# kolega-scan

[![CI](https://github.com/kolega-ai/kolega-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/kolega-ai/kolega-scan/actions/workflows/ci.yml)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11-blue.svg)](pyproject.toml)

LLM-assisted security scanner (SAST). Point it at a directory; get back structured,
[Semgrep-JSON-compatible](https://semgrep.dev/docs/cli-reference) findings. Storage- and
orchestration-agnostic — the package persists nothing and plugs into whatever pipeline you
already have.

## Install

```bash
# from source (PyPI release pending)
pip install git+https://github.com/kolega-ai/kolega-scan
```

## Scan your code

```bash
# the default scanner: the single-model LLM find-and-fix pipeline
# (set API creds first — see Credentials below)
kolega-scan scan ./my-project --out findings.json

# or pick a specific scanner
kolega-scan scan ./my-project --scanner kolega-scan-oss-v2 --out findings.json
```

The bundled [`demo/`](demo/) app is intentionally vulnerable — a good first target.

`findings.json` is Semgrep-compatible (`{"results": [...]}`), so it drops into any tooling
that already reads Semgrep output.

### Credentials

Models are addressed as `provider/model` (e.g. `deepseek/deepseek-v4-flash`,
`moonshot/kimi-k2.6`, `openai/gpt-5.4`, `anthropic/claude-opus-4-6`). By default each
provider is called **directly** — set that provider's own key:

```bash
export DEEPSEEK_API_KEY=...     # deepseek/*
export MOONSHOT_API_KEY=...     # moonshot/* (Kimi)
export OPENAI_API_KEY=...       # openai/*
export ANTHROPIC_API_KEY=...    # anthropic/*  (native Messages API)
```

Prefer to route everything through a **LiteLLM proxy** instead? Opt in and point at it:

```bash
export KOLEGA_LLM_BACKEND=litellm
export LITELLM_API_KEY=...
export LITELLM_URL=...           # or LITELLM_BASE_URL
```

## Scanners (`--scanner`)

Each scanner documents its own credential needs; the CLI itself is LLM-agnostic.

| `--scanner` | What it is |
|---|---|
| `kolega-scan-oss-v1` | **Default.** 2-model pipeline: DeepSeek **flash + pro**, findings combined. Needs `DEEPSEEK_API_KEY`. |
| `kolega-scan-oss-v2` | 3-model pipeline: adds **Kimi** to the DeepSeek pair for broadest coverage. Needs `DEEPSEEK_API_KEY` + `MOONSHOT_API_KEY`. |
| `kolega-scan-oss-ref` | Single-model reference pipeline, kept for development. |

The Kolega Scan OSS versions adapt Anthropic's
["Using LLMs to secure source code"](https://claude.com/blog/using-llms-to-secure-source-code)
five-phase workflow (threat model → discovery → verification → triage → variant hunt).

## Use it as a library

```python
from kolega_security_scanner import Finding, scan
```

The stable public surface (SemVer from 1.0.0) is documented in [`PUBLIC_API.md`](PUBLIC_API.md).

## Extend it

Ship your own scanner as a separate distribution and register it at runtime via the
`kolega_security_scanner.scanners` entry-point group — no fork required. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/dev/writing-scanners.md`](docs/dev/writing-scanners.md).

The bundled `detectors` scanner (`--scanner detectors`) is the internal dev example of
the extension seam: it runs the per-cluster reference-detector registry, needs no API
key, and picks up an LLM opportunistically when one is configured. See
[`docs/dev/writing-detectors.md`](docs/dev/writing-detectors.md).

## License

[Business Source License 1.1](LICENSE). Copyright 2026 KLG Tech Innovations Limited.

Not an open-source license today. You may use kolega-scan in production, including on
your own, your employer's, or your clients' code — the one thing the Additional Use
Grant excludes is offering it to third parties on a hosted or embedded basis as a
competitive paid offering. On the Change Date (2030-08-12) each version converts to
AGPL-3.0-or-later. See [LICENSE](LICENSE) for the terms that control.
