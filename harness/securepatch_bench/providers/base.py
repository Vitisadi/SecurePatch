"""Provider-agnostic model interface for the research harness.

This mirrors the TypeScript ``ModelProvider`` contract in
``core/src/interfaces/modelProvider.ts`` so result rows produced by the harness
and by the VS Code extension stay comparable. Concrete adapters
(OpenAI, Anthropic, ...) live alongside this module and implement ``complete``.

Pricing is kept here too: each call estimates a USD cost from token usage using
the published per-million-token rates below. The numbers are approximate and only
meant for the ``$/bug-found`` comparison axis, not billing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional


class ProviderError(RuntimeError):
    """Raised when a provider is misconfigured (missing key/SDK) or a call fails."""


@dataclass(frozen=True)
class ModelRequest:
    model: str
    prompt: str
    system: Optional[str] = None
    temperature: Optional[float] = None
    max_output_tokens: Optional[int] = None


@dataclass(frozen=True)
class ModelUsage:
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    latency_ms: Optional[float] = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": self.cost_usd,
            "latency_ms": self.latency_ms,
        }


@dataclass(frozen=True)
class ModelResponse:
    text: str
    usage: ModelUsage
    raw: Any = None  # untouched provider payload, retained for provenance


class ModelProvider(ABC):
    """One model vendor. ``id`` names it; ``default_model`` is used when a run
    does not pin a specific model."""

    id: str = "base"
    default_model: str = ""

    @abstractmethod
    def complete(self, request: ModelRequest) -> ModelResponse:
        """Run one completion. Must raise :class:`ProviderError` on failure."""


# USD per 1,000,000 tokens, as (input, output). Matched against a model id by
# longest-prefix so date-suffixed ids (e.g. claude-haiku-4-5-20251001) resolve.
# Anthropic rates: see the claude-api model table. OpenAI rates: published
# gpt-4.1 / gpt-4o pricing. Approximate; update when vendors change pricing.
PRICING: dict[str, tuple[float, float]] = {
    # OpenAI
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    # Anthropic
    "claude-fable-5": (10.00, 50.00),
    "claude-opus-4": (5.00, 25.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-haiku-4": (1.00, 5.00),
    # Google Gemini
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini-1.5-pro": (1.25, 5.00),
    "gemini-1.5-flash": (0.075, 0.30),
    # Ollama models run locally: cost is $0, set directly in the adapter (not here).
}


def _rate_for(model: str) -> Optional[tuple[float, float]]:
    best_key: Optional[str] = None
    for key in PRICING:
        if model.startswith(key) and (best_key is None or len(key) > len(best_key)):
            best_key = key
    return PRICING[best_key] if best_key else None


def estimate_cost(
    model: str,
    input_tokens: Optional[int],
    output_tokens: Optional[int],
) -> Optional[float]:
    """USD estimate for one call, or ``None`` if tokens or pricing are unknown."""
    if input_tokens is None or output_tokens is None:
        return None
    rate = _rate_for(model)
    if rate is None:
        return None
    return input_tokens / 1_000_000 * rate[0] + output_tokens / 1_000_000 * rate[1]
