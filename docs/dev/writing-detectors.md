# Writing Detectors

A detector finds one vulnerability cluster. Implement the `Detector` interface and
register it — bundled in-process, or external via an entry point.

## Interface

```python
from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass

class MyDetector(BaseDetector):
    slug = "ref-mycluster-r1"            # unique slug; appears in finding metadata
    cluster_id = "example_command_injection"   # free-form category label for this detector
    languages = ("python", "javascript", "typescript")
    detection_class = DetectionClass.FLOW

    def run(self, target, ctx):
        for sf in target.files:
            text = target.read_text(sf.path)
            ...
            yield self._finding(path=sf.path, line=42, cwe="CWE-78", message="...")
```

Rules:
- Every emitted finding's cluster MUST equal `self.cluster_id` (the engine rejects
  mismatches, isolating the detector).
- `ctx.llm is None` when no LLM is available; only use `ctx.llm` when it is present.
- Never raise to abort the whole scan — a crash is isolated and reported; other
  detectors keep running.
- `check_id` is auto-set to `kolega.<cluster_id>`.

## Registration

**External distribution** — add to your package's `pyproject.toml`:

```toml
[project.entry-points."kolega_security_scanner.detectors"]
ref-mycluster-r1 = "my_pkg.detectors:MyDetector"
```

The scanner discovers it automatically (the open-sourcing seam: the harness + some
detectors can be public while proprietary detectors ship in a private distribution).

**Bundled reference detectors** are registered in-process in
`detectors/registry.py:default_registry()`.

> **Whole-scanner plugins:** to ship an entire alternative scan pipeline (not one
> cluster) — e.g. a multi-pass LLM scanner — implement a `ScanProvider` instead of a
> detector. See [writing-scanners.md](./writing-scanners.md).

## LLM-aware detectors

Use `ctx.llm.complete(prompt)` (single-shot) or `ctx.llm.run_agent(...)` (agentic).
LLM output is non-deterministic — evaluate by repeated runs + aggregation; the
scanner builds no caching/replay.
