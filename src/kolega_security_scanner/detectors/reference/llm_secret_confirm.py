"""Reference LLM-assisted detector: regex secret candidates confirmed by the LLM.

Demonstrates the LLM-assisted path end-to-end: when a client is available it calls
``ctx.llm.chat_json`` to confirm each candidate; with no client it is a no-op. This is a
reference detector (like the Phase 5 ones), not a ported legacy detector.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass
from kolega_security_scanner.scanner.models import DetectorContext, ScanTarget
from kolega_security_scanner.schema.finding import Finding

_CANDIDATE = re.compile(
    r"(?i)\b(secret|password|passwd|api[_-]?key|apikey|token)\b\s*[:=]\s*[\"\'][^\"\'\n]{6,}[\"\']"
)


class LlmSecretConfirm(BaseDetector):
    """LLM-assisted detector: regex-find secret-ish literals, confirm via the LLM."""

    slug = "ref-llm-secret-confirm"
    cluster_id = "example_hardcoded_secret"
    languages: tuple[str, ...] = ("python", "javascript", "typescript")
    detection_class = DetectionClass.SEMANTIC

    def run(self, target: ScanTarget, ctx: DetectorContext) -> Iterable[Finding]:
        """Yield LLM-confirmed hardcoded-secret findings (only when a client is present)."""
        if ctx.llm is None:
            return  # no-op when no LLM client is available
        for sf in target.files:
            text = target.read_text(sf.path)
            for i, line in enumerate(text.splitlines(), start=1):
                if not _CANDIDATE.search(line):
                    continue
                verdict = ctx.llm.chat_json(
                    [
                        {
                            "role": "user",
                            "content": (
                                "Is the following line a hardcoded secret? "
                                'Reply JSON {"is_secret": true|false}.\n' + line.strip()
                            ),
                        }
                    ]
                )
                if isinstance(verdict, dict) and verdict.get("is_secret") is True:
                    yield self._finding(
                        path=sf.path,
                        line=i,
                        cwe="CWE-798",
                        message="LLM-confirmed hardcoded secret.",
                        severity="high",
                        confidence="high",
                    )
