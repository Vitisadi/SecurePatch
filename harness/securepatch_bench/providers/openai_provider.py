"""OpenAI adapter (Chat Completions API).

Reads the key from ``OPENAI_API_KEY`` (the SDK's default). The SDK is imported
lazily so the rest of the harness works without it installed; a clear
:class:`ProviderError` is raised if a run actually needs it.
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


class OpenAIProvider(ModelProvider):
    id = "openai"
    default_model = "gpt-4.1-mini"  # matches the VS Code extension's default

    def __init__(self) -> None:
        if not os.environ.get("OPENAI_API_KEY"):
            raise ProviderError(
                "OPENAI_API_KEY is not set; export it before running OpenAI scans."
            )
        try:
            import openai  # noqa: F401
        except ImportError as exc:
            raise ProviderError(
                "the 'openai' package is not installed; run "
                "`pip install -e .[providers]` from harness/."
            ) from exc
        self._client = openai.OpenAI()

    def complete(self, request: ModelRequest) -> ModelResponse:
        messages = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})

        kwargs: dict = {
            "model": request.model,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }
        if request.max_output_tokens:
            kwargs["max_tokens"] = request.max_output_tokens
        if request.temperature is not None:
            kwargs["temperature"] = request.temperature

        start = time.perf_counter()
        try:
            resp = self._client.chat.completions.create(**kwargs)
        except Exception as exc:  # noqa: BLE001 - surface any SDK/transport error
            raise ProviderError(f"OpenAI request failed: {exc}") from exc
        latency_ms = (time.perf_counter() - start) * 1000

        text = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        input_tokens = getattr(usage, "prompt_tokens", None)
        output_tokens = getattr(usage, "completion_tokens", None)

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
