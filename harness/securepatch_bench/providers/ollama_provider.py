"""Ollama adapter (local models via the ollama SDK).

Talks to a local Ollama server (default ``http://localhost:11434``, override with
``OLLAMA_HOST``). No API key — the model runs on your machine, so cost is $0 by
construction; only latency and tokens are meaningful. The SDK is imported lazily.

``format="json"`` asks the model for a JSON object so the detector/fixer parsers
get clean output, mirroring the OpenAI/Gemini adapters. Note that local models
vary a lot in how well they honor this — the parsers already degrade gracefully
on malformed JSON.
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
)


class OllamaProvider(ModelProvider):
    id = "ollama"
    default_model = "llama3.1"

    def __init__(self) -> None:
        try:
            import ollama
        except ImportError as exc:
            raise ProviderError(
                "the 'ollama' package is not installed; run "
                "`pip install -e .[providers]` from harness/."
            ) from exc
        # A generous per-request timeout: enough for a cold model load from disk,
        # but bounded so a hung local server fails the call instead of blocking
        # the whole run forever (override with OLLAMA_TIMEOUT seconds).
        timeout = float(os.environ.get("OLLAMA_TIMEOUT", "600"))
        host = os.environ.get("OLLAMA_HOST")
        self._client = ollama.Client(host=host, timeout=timeout)

    def complete(self, request: ModelRequest) -> ModelResponse:
        messages = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})

        options: dict = {}
        if request.temperature is not None:
            options["temperature"] = request.temperature
        if request.max_output_tokens:
            options["num_predict"] = request.max_output_tokens

        start = time.perf_counter()
        try:
            resp = self._client.chat(
                model=request.model,
                messages=messages,
                format="json",
                options=options or None,
            )
        except Exception as exc:  # noqa: BLE001 - server down, model not pulled, etc.
            raise ProviderError(
                f"Ollama request failed (is the server running and '{request.model}' "
                f"pulled?): {exc}"
            ) from exc
        latency_ms = (time.perf_counter() - start) * 1000

        text = _message_content(resp)
        return ModelResponse(
            text=text,
            usage=ModelUsage(
                input_tokens=_get(resp, "prompt_eval_count"),
                output_tokens=_get(resp, "eval_count"),
                cost_usd=0.0,  # local inference — free by construction
                latency_ms=latency_ms,
            ),
            raw=_as_dict(resp),
        )


def _message_content(resp: object) -> str:
    """Pull message.content from either a dict or the SDK's response object."""
    if isinstance(resp, dict):
        return (resp.get("message") or {}).get("content", "") or ""
    message = getattr(resp, "message", None)
    return getattr(message, "content", "") or ""


def _get(resp: object, key: str):
    if isinstance(resp, dict):
        return resp.get(key)
    return getattr(resp, key, None)


def _as_dict(resp: object):
    if isinstance(resp, dict):
        return resp
    if hasattr(resp, "model_dump"):
        return resp.model_dump()
    return None
