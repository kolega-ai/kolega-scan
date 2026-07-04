"""The multi-model claude-adaptation variants register and are configured right."""

from kolega_security_scanner.scanner.providers import default_provider_registry
from kolega_security_scanner.scanners.claude_adaptation.config import (
    DEEPSEEK_MATRIX_MODELS,
    DEEPSEEK_VARIANT_NAME,
    KIMI_ENSEMBLE_MODELS,
    KIMI_ENSEMBLE_VARIANT_NAME,
    PROVIDER_NAME,
)
from kolega_security_scanner.scanners.claude_adaptation.provider import (
    build_deepseek_matrix_provider,
    build_kimi_ensemble_provider,
    build_provider,
)


def test_variants_register_in_default_registry():
    names = set(default_provider_registry(include_entry_points=False).names())
    assert {PROVIDER_NAME, DEEPSEEK_VARIANT_NAME, KIMI_ENSEMBLE_VARIANT_NAME} <= names


def test_base_provider_is_single_model():
    p = build_provider()
    assert p.name == PROVIDER_NAME
    assert p._cfg.discovery_models == ()
    assert p._cfg.verify_models == ()


def test_deepseek_variant_runs_flash_and_pro():
    p = build_deepseek_matrix_provider()
    assert p.name == DEEPSEEK_VARIANT_NAME
    assert (
        p._cfg.discovery_models
        == DEEPSEEK_MATRIX_MODELS
        == ("deepseek/deepseek-v4-flash", "deepseek/deepseek-v4-pro")
    )
    assert p._cfg.verify_models == DEEPSEEK_MATRIX_MODELS
    assert p._cfg.combine == "union"


def test_kimi_ensemble_adds_kimi():
    p = build_kimi_ensemble_provider()
    assert p.name == KIMI_ENSEMBLE_VARIANT_NAME
    assert "moonshot/kimi-k2.6" in p._cfg.discovery_models
    assert p._cfg.discovery_models == KIMI_ENSEMBLE_MODELS
