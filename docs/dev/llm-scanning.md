# LLM-Assisted Scanning

There is no mode flag, and the CLI is fully LLM-agnostic: it never builds or injects an
LLM client. Each scanner owns its own credential needs and builds its client(s) inside
`scan()`: the LLM pipeline scanners require a key (missing key = usage error, exit 2),
while the `detectors` provider builds one opportunistically and runs with or without it —
LLM-aware detectors simply activate when a client is available.

## Configure

By default each provider is called directly — set that provider's own key:
```
DEEPSEEK_API_KEY=...           # deepseek/*   (default model)
MOONSHOT_API_KEY=...           # moonshot/*   (Kimi)
OPENAI_API_KEY=...             # openai/*
ANTHROPIC_API_KEY=...          # anthropic/*
```
To route everything through a LiteLLM proxy instead, opt in:
```
KOLEGA_LLM_BACKEND=litellm
LITELLM_API_KEY=...
LITELLM_URL=https://.../v1     # or LITELLM_BASE_URL
```
These may also be placed in a git-ignored `.env` at the directory you run from.

## Run
```bash
kolega-scan scan ./my-project --out scan-out/findings.json
```
- A scanner that requires an LLM fails fast (exit 2) when no key is configured. For an
  offline run, use `--scanner detectors` (it needs no key).
- LLM output is non-deterministic: **evaluate by repeated runs + aggregation** (mean/stddev);
  the scanner builds no caching/replay.

## Tests / CI
- All automated tests use an offline `FakeLLMClient` — **CI makes zero network calls**.
- A real end-to-end smoke test is opt-in: `KOLEGA_LLM_LIVE=1 pytest tests/cli/test_scan_live.py`.

## Security
- The API key is read from the environment (or repo-root `.env`) and **never logged or
  echoed in errors**. `.env` is git-ignored.
