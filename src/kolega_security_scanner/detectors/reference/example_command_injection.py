"""Reference detector: OS command injection sinks (FLOW-ish, python + js/ts)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass
from kolega_security_scanner.scanner.models import DetectorContext, ScanTarget
from kolega_security_scanner.schema.finding import Finding

_PY_SINK = re.compile(r"\bos\.system\s*\(|\bshell\s*=\s*True\b")
_JS_SINK = re.compile(r"\.exec\s*\(")


class CommandInjectionOsSystem(BaseDetector):
    """Flags os.system / shell=True (python) and child_process.exec (js/ts)."""

    slug = "ref-command-injection-os-system"
    cluster_id = "example_command_injection"
    languages: tuple[str, ...] = ("python", "javascript", "typescript")
    detection_class = DetectionClass.FLOW

    def run(self, target: ScanTarget, ctx: DetectorContext) -> Iterable[Finding]:
        """Yield command-injection findings for shell sinks."""
        for sf in target.files:
            pattern = _PY_SINK if sf.language == "python" else _JS_SINK
            text = target.read_text(sf.path)
            for i, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    yield self._finding(
                        path=sf.path,
                        line=i,
                        cwe="CWE-78",
                        message=(
                            "OS command executed via a shell sink; "
                            "verify input is not attacker-controlled."
                        ),
                        severity="high",
                        confidence="medium",
                    )
