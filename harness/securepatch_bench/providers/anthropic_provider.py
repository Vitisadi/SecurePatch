"""Anthropic (Claude) adapter (Messages API).

Reads the key from ``ANTHROPIC_API_KEY`` (the SDK's default). The SDK is imported
lazily so the rest of the harness works without it installed.

Notes on the request shape:
- ``temperature`` is intentionally never sent. The current Opus models reject
  sampling parameters (400), and leaving it unset lets natural sampling produce
  the run-to-run variation the multi-scan experiment measures.
- The ``thinking`` parameter is omitted, so the model answers without extended
  thinking — cheaper, and the response is plain text we can JSON-parse directly.
"""

from __future__ import annotations

import os
import time

from .base import (
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ProviderError,
    estimate_cost,
)


class AnthropicProvider(ModelProvider):
    id = "anthropic"
    default_model = "claude-opus-4-8"

    def __init__(self) -> None:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ProviderError(
                "ANTHROPIC_API_KEY is not set; export it before running Claude scans."
            )
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:
            raise ProviderError(
                "the 'anthropic' package is not installed; run "
                "`pip install -e .[providers]` from harness/."
            ) from exc
        self._client = anthropic.Anthropic()

    def complete(self, request: ModelRequest) -> ModelResponse:
        kwargs: dict = {
            "model": request.model,
            "max_tokens": request.max_output_tokens or 4096,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if request.system:
            kwargs["system"] = request.system

        start = time.perf_counter()
        try:
            resp = self._client.messages.create(**kwargs)
        except Exception as exc:  # noqa: BLE001 - surface any SDK/transport error
            raise ProviderError(f"Anthropic request failed: {exc}") from exc
        latency_ms = (time.perf_counter() - start) * 1000

        text = "".join(
            block.text
            for block in resp.content
            if getattr(block, "type", None) == "text"
        )
        usage = getattr(resp, "usage", None)
        input_tokens = getattr(usage, "input_tokens", None)
        output_tokens = getattr(usage, "output_tokens", None)

        return ModelResponse(
            text=text,
            usage=ModelUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=estimate_cost(request.model, input_tokens, output_tokens),
                latency_ms=latency_ms,
            ),
            raw=resp.model_dump() if hasattr(resp, "model_dump") else None,
        )
