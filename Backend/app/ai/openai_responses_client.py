from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from app.ai.retry import RetryPolicy, should_retry_http, sleep_backoff
from app.ai.error_handling import AiServiceError, normalize_openai_error
from app.core.config import settings


class OpenAIResponsesClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: float = 60.0,
        retry_policy: RetryPolicy = RetryPolicy(),
    ) -> None:
        self.api_key = api_key or settings.openai_api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.retry_policy = retry_policy

    async def analyze(self, *, system: str, prompt: str, max_output_tokens: int) -> Any:
        if not self.api_key:
            raise AiServiceError(
                message="OpenAI API key is not configured.",
                code="openai_missing_api_key",
            )

        url = f"{self.base_url}/responses"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # Use the Responses API with JSON mode hints via instructions.
        # We rely on our parser + schema validation.
        payload: dict[str, Any] = {
            "model": os.getenv("OPENAI_RESPONSES_MODEL", "gpt-4.1-mini"),
            "input": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_output_tokens": max_output_tokens,
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            last_exc: Exception | None = None
            for attempt in range(1, self.retry_policy.max_attempts + 1):
                try:
                    resp = await client.post(url, headers=headers, json=payload)
                    if should_retry_http(resp.status_code) and attempt < self.retry_policy.max_attempts:
                        await sleep_backoff(attempt, self.retry_policy)
                        continue

                    if resp.status_code >= 400:
                        raise AiServiceError(
                            message="OpenAI request failed",
                            code="openai_http_error",
                            details=normalize_openai_error(resp.json() if resp.content else None),
                        )

                    data = resp.json()

                    # Responses API returns output in structured fields; best-effort extraction.
                    # Common patterns include data['output'] items with 'content'.
                    return data
                except (httpx.TimeoutException, httpx.NetworkError) as e:
                    last_exc = e
                    if attempt < self.retry_policy.max_attempts:
                        await sleep_backoff(attempt, self.retry_policy)
                        continue
                    raise AiServiceError(
                        message="Network error contacting OpenAI",
                        code="openai_network_error",
                        details=str(last_exc),
                    )

        raise AiServiceError(message="OpenAI request failed", code="openai_unknown")

