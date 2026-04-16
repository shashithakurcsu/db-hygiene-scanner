"""Anthropic API client wrapper with retry, rate limiting, and audit logging."""

import asyncio
import hashlib
import json
import re
import time
from typing import Any, Optional

import structlog

from db_hygiene_scanner.ai_engine.constants import (
    DEFAULT_MAX_CONCURRENT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_DELAYS,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_TOKENS_PER_REQUEST,
    MODEL_PRICING,
)
from db_hygiene_scanner.ai_engine.prompts import SYSTEM_MESSAGE
from db_hygiene_scanner.config import Config
from db_hygiene_scanner.utils.security import compute_code_hash


class AIClient:
    """Robust Anthropic API client with retry, rate limiting, and audit logging."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        self.config = config
        self.logger = logger
        self._client: Any = None
        self._async_client: Any = None
        self._request_count = 0
        self._window_start = time.time()
        self._semaphore = asyncio.Semaphore(DEFAULT_MAX_CONCURRENT)

    def _get_client(self) -> Any:
        """Lazily initialize the Anthropic client."""
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.config.anthropic_api_key)
        return self._client

    def _get_async_client(self) -> Any:
        """Lazily initialize the async Anthropic client."""
        if self._async_client is None:
            import anthropic
            self._async_client = anthropic.AsyncAnthropic(api_key=self.config.anthropic_api_key)
        return self._async_client

    def call(
        self,
        prompt: str,
        model: str,
        system: str = SYSTEM_MESSAGE,
        max_tokens: int = MAX_TOKENS_PER_REQUEST,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        """Make a synchronous API call with retry and rate limiting.

        Args:
            prompt: User message content.
            model: Model identifier.
            system: System message.
            max_tokens: Maximum response tokens.
            timeout: Request timeout in seconds.

        Returns:
            Dict with 'content', 'model', 'usage', 'latency_ms' keys.
        """
        self._enforce_rate_limit()
        input_hash = compute_code_hash(prompt)

        for attempt in range(DEFAULT_MAX_RETRIES):
            start_time = time.time()
            try:
                client = self._get_client()
                response = client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": prompt}],
                    timeout=timeout,
                )

                latency_ms = (time.time() - start_time) * 1000
                result = {
                    "content": response.content[0].text,
                    "model": response.model,
                    "usage": {
                        "input_tokens": response.usage.input_tokens,
                        "output_tokens": response.usage.output_tokens,
                    },
                    "latency_ms": latency_ms,
                }

                self.logger.info(
                    "api_call_success",
                    model=model,
                    input_hash=input_hash,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    latency_ms=f"{latency_ms:.0f}",
                )

                return result

            except Exception as e:
                delay = DEFAULT_RETRY_DELAYS[attempt] if attempt < len(DEFAULT_RETRY_DELAYS) else 4.0
                self.logger.warning(
                    "api_call_retry",
                    attempt=attempt + 1,
                    error=str(e),
                    delay=delay,
                )
                if attempt == DEFAULT_MAX_RETRIES - 1:
                    self.logger.error("api_call_failed", error=str(e), model=model)
                    return {
                        "content": "",
                        "model": model,
                        "usage": {"input_tokens": 0, "output_tokens": 0},
                        "latency_ms": 0,
                        "error": str(e),
                    }
                time.sleep(delay)

        return {"content": "", "model": model, "usage": {}, "latency_ms": 0, "error": "max retries exceeded"}

    async def async_call(
        self,
        prompt: str,
        model: str,
        system: str = SYSTEM_MESSAGE,
        max_tokens: int = MAX_TOKENS_PER_REQUEST,
    ) -> dict[str, Any]:
        """Make an async API call with semaphore-based concurrency control."""
        async with self._semaphore:
            start_time = time.time()
            try:
                client = self._get_async_client()
                response = await client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": prompt}],
                )
                latency_ms = (time.time() - start_time) * 1000
                return {
                    "content": response.content[0].text,
                    "model": response.model,
                    "usage": {
                        "input_tokens": response.usage.input_tokens,
                        "output_tokens": response.usage.output_tokens,
                    },
                    "latency_ms": latency_ms,
                }
            except Exception as e:
                self.logger.error("async_api_call_failed", error=str(e))
                return {"content": "", "model": model, "usage": {}, "error": str(e)}

    def estimate_cost(self, prompt: str, model_name: str) -> float:
        """Estimate cost for a request in USD.

        Args:
            prompt: The prompt text.
            model_name: Model to use.

        Returns:
            Estimated cost in USD.
        """
        # Rough estimate: ~4 chars per token
        est_tokens = len(prompt) / 4
        pricing = MODEL_PRICING.get(model_name, {"input": 3.0, "output": 15.0})
        input_cost = (est_tokens / 1_000_000) * pricing["input"]
        output_cost = (MAX_TOKENS_PER_REQUEST / 1_000_000) * pricing["output"]
        return input_cost + output_cost

    def _enforce_rate_limit(self) -> None:
        """Enforce sliding-window rate limiting."""
        current_time = time.time()
        window_elapsed = current_time - self._window_start

        if window_elapsed >= 60:
            self._request_count = 0
            self._window_start = current_time

        if self._request_count >= self.config.rate_limit_rpm:
            sleep_time = 60 - window_elapsed
            if sleep_time > 0:
                self.logger.info("rate_limit_wait", seconds=f"{sleep_time:.1f}")
                time.sleep(sleep_time)
            self._request_count = 0
            self._window_start = time.time()

        self._request_count += 1

    @staticmethod
    def parse_json_response(content: str) -> dict[str, Any]:
        """Extract and parse JSON from an API response.

        Handles responses wrapped in markdown code blocks (```json ... ```).

        Args:
            content: Raw response text from the API.

        Returns:
            Parsed dict from the JSON content.

        Raises:
            json.JSONDecodeError: If no valid JSON can be extracted.
        """
        # Try direct parse first
        text = content.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting from markdown code blocks
        patterns = [
            r"```json\s*\n(.*?)```",
            r"```\s*\n(.*?)```",
            r"\{.*\}",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                candidate = match.group(1) if match.lastindex else match.group(0)
                try:
                    return json.loads(candidate.strip())
                except json.JSONDecodeError:
                    continue

        raise json.JSONDecodeError("No valid JSON found in response", text, 0)
