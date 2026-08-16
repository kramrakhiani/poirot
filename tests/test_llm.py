import pytest

from poirot.llm import PROVIDERS, CLOUD_PROVIDERS, _model_memory_gb, recommend_local_model
from poirot.llm import explain


def test_cloud_and_local_options_are_registered():
    assert {"openai", "anthropic", "google", "ollama", "local"} <= set(PROVIDERS)


def test_cloud_providers_are_identified():
    assert "openai" in CLOUD_PROVIDERS
    assert "anthropic" in CLOUD_PROVIDERS
    assert "openrouter" in CLOUD_PROVIDERS
    assert "ollama" not in CLOUD_PROVIDERS
    assert "local" not in CLOUD_PROVIDERS


def test_recommendation_has_hardware_and_model():
    result = recommend_local_model()
    assert result["hardware"]["cpu"]["architecture"]
    assert result["recommendation"]["model"]
    assert result["decision"]["usable_model_memory_budget_gb"] > 0
    assert result["recommendation"]["install_command"].startswith("ollama pull ")
    assert "alternatives" not in result


def test_larger_models_require_more_memory():
    assert _model_memory_gb(32, "Q4_K_M") > _model_memory_gb(7, "Q4_K_M")


def test_cloud_explanation_requires_explicit_consent():
    with pytest.raises(ValueError, match="disabled by default"):
        explain({}, "openai")


def test_unknown_provider_gives_actionable_error():
    with pytest.raises(ValueError, match="Unknown provider"):
        explain({}, "not-a-real-provider")
