"""The Kolega Scan OSS versions: an LLM find-and-fix loop.

Ships ``kolega-scan-oss-v1`` (default, 2-model DeepSeek flash+pro), ``kolega-scan-oss-v2``
(3-model, adds Kimi), and ``kolega-scan-oss-ref`` (single-model reference pipeline).

Adapts Anthropic's "Using LLMs to secure source code" six-phase workflow
(https://claude.com/blog/using-llms-to-secure-source-code) to this harness. See
``provider.py`` for the phase orchestration and ``docs/dev/claude-adaptation-scanner.md``
for the mapping and the parts intentionally omitted (human interview, sandbox PoC exec,
patching).
"""

from __future__ import annotations

from kolega_security_scanner.scanners.claude_adaptation.config import (
    DEEPSEEK_VARIANT_NAME,
    KIMI_ENSEMBLE_VARIANT_NAME,
    PROVIDER_NAME,
)
from kolega_security_scanner.scanners.claude_adaptation.provider import (
    ClaudeAdaptationScanProvider,
    build_deepseek_matrix_provider,
    build_kimi_ensemble_provider,
    build_provider,
)

__all__ = [
    "PROVIDER_NAME",
    "DEEPSEEK_VARIANT_NAME",
    "KIMI_ENSEMBLE_VARIANT_NAME",
    "ClaudeAdaptationScanProvider",
    "build_provider",
    "build_deepseek_matrix_provider",
    "build_kimi_ensemble_provider",
]
