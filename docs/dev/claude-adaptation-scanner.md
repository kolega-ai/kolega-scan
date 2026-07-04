# `kolega-scan-oss-ref` — the single-model reference pipeline

An LLM-driven adaptation of Anthropic's
[*Using LLMs to secure source code*](https://claude.com/blog/using-llms-to-secure-source-code)
"find-and-fix loop", implemented as a `ScanProvider` over this harness's `LLMClient`.
The shipped versions `kolega-scan-oss-v1` (default, 2-model DeepSeek flash+pro) and
`kolega-scan-oss-v2` (3-model, adds Kimi) run this same pipeline across multiple
models; `--scanner kolega-scan-oss-ref` is the single-model form, kept for
development. The deterministic reference-detector provider remains available as
`--scanner detectors`.

## Why this exists

The article's thesis is that LLM-based **discovery** is now fast and parallelizable, so
the bottleneck moves to **verification** and **triage**. This scanner encodes that loop
directly instead of hand-writing per-cluster detectors.

## Phase mapping

| Article phase | Module | Notes |
|---|---|---|
| 1. Threat modeling | `threat_model.py` | Code-driven derivation only. The **human interview is omitted** — the CLI is non-interactive (the one deliberate divergence from the article). |
| 2. Sandboxing | — | No sandbox/PoC execution in a findings-only CLI. Verification is therefore **code-analysis only**, which the article explicitly permits at lower precision. |
| 3. Discovery | `partition.py`, `discovery.py` | Partition by attack surface (top-level component), then one independent structured pass per partition so agents don't converge on shallow bugs. Output ordered rationale → finding → impact → severity, with an escape hatch for "nothing found". |
| 4. Verification | `verification.py` | A fresh, independent verifier per candidate with **no discovery context**, prompted to *disprove* the finding. `verifiers > 1` runs N independent verifiers and takes a strict majority vote. |
| 5. Triage | `triage.py` | Deterministic dedupe (same file + vuln-class within a 10-line proximity window → one bug, highest-severity representative kept) then severity ranking. |
| 6. Patching / variant hunt | `discovery.py` (`discover_variants`) | **Variant search is implemented** (agentic runs): confirmed findings seed a follow-up discovery pass that hunts for more instances of the same patterns elsewhere in the repo; the variants are then verified before being merged into the results. Patch generation stays out of scope for a scanner that emits findings. |

The threat model is injected as context into discovery, verification, and triage — the
article's primary false-positive lever ("threat model grounding").

## Pipeline flow

```
enumerate sources
  └─ Phase 1: build_threat_model            (1 LLM call)
  └─ Phase 3: partition_files → discover_partition per partition   (1 call / partition)
  └─ Phase 4: verify_candidate per candidate (drop unconfirmed)    (verifiers calls / candidate)
  └─ Phase 6: discover_variants seeded with confirmed findings, then verify (agentic runs)
  └─ Phase 5: triage (dedupe + rank)         (deterministic, 0 LLM calls)
  └─ to_finding → ScanResult.findings (Semgrep-compatible)
```

## Configuration

`PipelineConfig` (`config.py`) holds all budgets — partition size, per-file/per-prompt
char caps, candidate cap, verifier count, and context window. Defaults are tuned for the
`deepseek-v4-flash` default model.

## Model & credentials

The pipeline is LLM-driven, so it **requires** a client. The provider builds one from the
environment and raises a clear `LLMConfigError` if no API key is configured — the
provider-native key for the model (e.g. `$DEEPSEEK_API_KEY` for the default
`deepseek/deepseek-v4-flash`), or `$LITELLM_API_KEY` when `KOLEGA_LLM_BACKEND=litellm`.
There is intentionally **no deterministic fallback** — for an offline run,
select `--scanner detectors`.

## Output

Confirmed findings are emitted as standard Semgrep-compatible `Finding`s with
`check_id = kolega.claude-adaptation.<vuln-class>`, a sanitized CWE (fallback `CWE-693`),
and the verifier's recalibrated severity when present.

## Future work

- Model-based dedupe qualification on top of the deterministic pass (Phase 5).
- Parallel discovery/verification fan-out (currently sequential).
- Optional sandbox + PoC execution to lift verification precision (Phase 2 / patch ladder).
- Patch generation (Phase 6) — variant search is already implemented.
