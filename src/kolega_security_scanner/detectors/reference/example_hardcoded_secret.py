"""Reference detector: hardcoded secret literals (REGEX, multilang)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass
from kolega_security_scanner.scanner.models import DetectorContext, ScanTarget
from kolega_security_scanner.schema.finding import Finding

_SECRET = re.compile(
    r"(?i)\b(secret|password|passwd|api[_-]?key|apikey|token|access[_-]?key)\b"
    r"\s*[:=]\s*[\"\\'][^\"\\'\n]{6,}[\"\\']"
)


class HardcodedSecretLiteral(BaseDetector):
    """Flags secret-named variables assigned a string literal."""

    slug = "ref-hardcoded-secret-literal"
    cluster_id = "example_hardcoded_secret"
    languages: tuple[str, ...] = ("python", "javascript", "typescript")
    detection_class = DetectionClass.REGEX

    def run(self, target: ScanTarget, ctx: DetectorContext) -> Iterable[Finding]:
        """Yield findings for credential-named variables assigned string literals."""
        for sf in target.files:
            text = target.read_text(sf.path)
            for i, line in enumerate(text.splitlines(), start=1):
                if _SECRET.search(line):
                    yield self._finding(
                        path=sf.path,
                        line=i,
                        cwe="CWE-798",
                        message=(
                            "Possible hardcoded secret assigned to a credential-named variable."
                        ),
                        severity="high",
                        confidence="medium",
                    )
