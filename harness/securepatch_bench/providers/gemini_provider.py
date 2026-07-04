"""Google Gemini adapter (google-genai SDK).

Reads the key from ``GEMINI_API_KEY`` (falling back to ``GOOGLE_API_KEY``, which
the SDK also honors). The SDK is imported lazily so the rest of the harness works
without it installed.

Like the OpenAI adapter, this requests a JSON response
(``response_mime_type="application/json"``) so the detector/fixer parsers get
clean JSON. Temperature is only sent when explicitly set, leaving natural
sampling for the multi-scan experiment.
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

# Free-tier Gemini is aggressively rate-limited (429 RESOURCE_EXHAUSTED). Retry a
# few times with exponential backoff so a long benchmark run rides through the
# per-minute caps instead of erroring out.
_MAX_RETRIES = 5
_BACKOFF_BASE_S = 8.0


class GeminiProvider(ModelProvider):
    id = "gemini"
    default_model = "gemini-2.5-flash"  # 2.0-flash has zero free-tier quota

    def __init__(self) -> None:
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ProviderError(
                "GEMINI_API_KEY (or GOOGLE_API_KEY) is not set; export it before "
                "running Gemini scans."
            )
        try:
            from google import genai  # noqa: F401
        except ImportError as exc:
            raise ProviderError(
                "the 'google-genai' package is not installed; run "
                "`pip install -e .[providers]` from harness/."
            ) from exc
        self._client = genai.Client(api_key=api_key)

    def complete(self, request: ModelRequest) -> ModelResponse:
        config: dict = {"response_mime_type": "application/json"}
        if request.system:
            config["system_instruction"] = request.system
        if request.max_output_tokens:
            config["max_output_tokens"] = request.max_output_tokens
        if request.temperature is not None:
            config["temperature"] = request.temperature

        start = time.perf_counter()
        resp = self._generate_with_retry(request, config)
        latency_ms = (time.perf_counter() - start) * 1000

        text = getattr(resp, "text", None) or ""
        usage = getattr(resp, "usage_metadata", None)
        input_tokens = getattr(usage, "prompt_token_count", None)
        output_tokens = getattr(usage, "candidates_token_count", None)

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

    def _generate_with_retry(self, request: ModelRequest, config: dict):
        """Call generate_content, retrying rate-limit (429) errors with backoff."""
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                return self._client.models.generate_content(
                    model=request.model, contents=request.prompt, config=config
                )
            except Exception as exc:  # noqa: BLE001 - inspect for rate limiting
                last_exc = exc
                if not _is_rate_limit(exc) or attempt == _MAX_RETRIES - 1:
                    raise ProviderError(f"Gemini request failed: {exc}") from exc
                time.sleep(_BACKOFF_BASE_S * (2**attempt))
        raise ProviderError(f"Gemini request failed: {last_exc}")  # unreachable


def _is_rate_limit(exc: Exception) -> bool:
    text = str(exc).lower()
    return "429" in text or "resource_exhausted" in text or "rate limit" in text
