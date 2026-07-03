"""Model provider adapters for the research harness.

Each provider implements the :class:`ModelProvider` interface in ``base`` and is
constructed via :func:`get_provider`. Provider SDKs are imported lazily inside
each adapter, so importing this package never requires the SDKs to be installed.
"""

from __future__ import annotations

from .anthropic_provider import AnthropicProvider
from .base import (
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ProviderError,
    estimate_cost,
)
from .gemini_provider import GeminiProvider
from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider

PROVIDERS: dict[str, type[ModelProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def get_provider(provider_id: str) -> ModelProvider:
    """Instantiate a provider by id (validates key/SDK eagerly)."""
    try:
        provider_cls = PROVIDERS[provider_id]
    except KeyError:
        raise ProviderError(
            f"unknown provider '{provider_id}' (known: {sorted(PROVIDERS)})"
        ) from None
    return provider_cls()


__all__ = [
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ModelUsage",
    "ProviderError",
    "estimate_cost",
    "PROVIDERS",
    "get_provider",
]
