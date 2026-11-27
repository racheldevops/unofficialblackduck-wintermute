from __future__ import annotations

import json
import ssl
import threading
import time
from collections import deque
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from wintermute.ai.config import AISettings
from wintermute.ai.models import (
    ModelResponse,
    ModelUsage,
)


MAX_RESPONSE_BYTES = 16 * 1024 * 1024
COMPATIBLE_TEMPERATURE = 1
RETRYABLE_STATUSES = {
    408,
    409,
    425,
    429,
    500,
    502,
    503,
    504,
}


def combined_usage(
    first: ModelUsage,
    second: ModelUsage,
) -> ModelUsage:
    return ModelUsage(
        input_tokens=(
            first.input_tokens
            + second.input_tokens
        ),
        output_tokens=(
            first.output_tokens
            + second.output_tokens
        ),
        cached_input_tokens=(
            first.cached_input_tokens
            + second.cached_input_tokens
        ),
        reasoning_tokens=(
            first.reasoning_tokens
            + second.reasoning_tokens
        ),
    )


class AIProviderError(RuntimeError):
    def __init__(
        self,
        category: str,
        message: str,
        *,
        attempts: int,
        status_code: int | None = None,
        usage: ModelUsage | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.attempts = attempts
        self.status_code = status_code
        self.usage = usage or ModelUsage()


class OpenAICompatibleProvider:
    def __init__(
        self,
        settings: AISettings,
        *,
        sleeper: Any = time.sleep,
    ) -> None:
        settings.validate()
        self.settings = settings
        self._sleeper = sleeper
        self._lock = threading.RLock()
        self._next_request_at = 0.0
        self._failures: deque[float] = (
            deque()
        )

        if settings.insecure:
            self.ssl_context = (
                ssl._create_unverified_context()
            )
        elif settings.ca_bundle:
            self.ssl_context = (
                ssl.create_default_context(
                    cafile=settings.ca_bundle
                )
            )
        else:
            self.ssl_context = None

    def complete(
        self,
        messages: list[dict[str, str]],
    ) -> ModelResponse:
        payload = {
            "model": self.settings.model,
            "messages": messages,
            "temperature": (
                COMPATIBLE_TEMPERATURE
            ),
            "max_tokens": (
                self.settings.max_output_tokens
            ),
            "response_format": {
                "type": "json_object"
            },
        }
        body = json.dumps(
            payload,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        url = self._request_url()
        previous_usage = ModelUsage()

        for attempt in range(
            self.settings.retries + 1
        ):
            self._before_request()
            request = Request(
                url,
                data=body,
                headers=self._headers(),
                method="POST",
            )

            try:
                with urlopen(
                    request,
                    timeout=(
                        self.settings
                        .timeout_seconds
                    ),
                    context=self.ssl_context,
                ) as response:
                    content = response.read(
                        MAX_RESPONSE_BYTES + 1
                    )
                    status = int(
                        getattr(
                            response,
                            "status",
                            200,
                        )
                    )
                    headers = getattr(
                        response,
                        "headers",
                        {},
                    )

                if len(content) > MAX_RESPONSE_BYTES:
                    raise AIProviderError(
                        "invalid_response",
                        "AI response exceeded the "
                        "maximum supported size",
                        attempts=attempt + 1,
                        status_code=status,
                    )

                if status != 200:
                    if (
                        status
                        in RETRYABLE_STATUSES
                        and attempt
                        < self.settings.retries
                    ):
                        self._record_failure()
                        self._retry(
                            attempt,
                            headers,
                        )
                        continue

                    raise AIProviderError(
                        "http_error",
                        "AI endpoint returned "
                        f"HTTP {status}",
                        attempts=attempt + 1,
                        status_code=status,
                    )

                try:
                    parsed = (
                        self._parse_response(
                            content,
                            headers,
                            attempt + 1,
                        )
                    )
                except AIProviderError as error:
                    previous_usage = (
                        combined_usage(
                            previous_usage,
                            error.usage,
                        )
                    )

                    if (
                        error.category
                        == "empty_response"
                        and attempt
                        < self.settings.retries
                    ):
                        self._record_failure()
                        self._retry(
                            attempt,
                            headers,
                        )
                        continue

                    raise

                self._record_success()

                return ModelResponse(
                    content=parsed.content,
                    usage=combined_usage(
                        previous_usage,
                        parsed.usage,
                    ),
                    request_id=(
                        parsed.request_id
                    ),
                )

            except HTTPError as error:
                body_text = error.read(
                    4000
                ).decode(
                    "utf-8",
                    errors="replace",
                )
                body_text = self._redact(
                    body_text
                )
                retryable = (
                    error.code
                    in RETRYABLE_STATUSES
                )

                if (
                    retryable
                    and attempt
                    < self.settings.retries
                ):
                    self._record_failure()
                    self._retry(
                        attempt,
                        error.headers,
                    )
                    continue

                if error.code == 400:
                    category = (
                        "invalid_request"
                    )
                elif error.code == 401:
                    category = (
                        "authentication_failed"
                    )
                elif error.code == 403:
                    category = (
                        "authorization_failed"
                    )
                elif error.code == 429:
                    category = "rate_limited"
                else:
                    category = "http_error"

                raise AIProviderError(
                    category,
                    "AI request failed: "
                    f"HTTP {error.code}: "
                    f"{body_text}",
                    attempts=attempt + 1,
                    status_code=error.code,
                ) from error

            except AIProviderError:
                raise

            except (
                URLError,
                TimeoutError,
                OSError,
            ) as error:
                self._record_failure()

                if attempt < self.settings.retries:
                    self._retry(
                        attempt,
                        {},
                    )
                    continue

                raise AIProviderError(
                    "network_error",
                    "AI network request failed: "
                    f"{type(error).__name__}: "
                    f"{self._redact(str(error))}",
                    attempts=attempt + 1,
                ) from error

        raise AIProviderError(
            "unexpected_error",
            "AI request failed unexpectedly",
            attempts=self.settings.retries + 1,
            usage=previous_usage,
        )

    def _request_url(self) -> str:
        endpoint = (
            self.settings.endpoint.rstrip("/")
        )

        if self.settings.provider == "azure":
            return (
                f"{endpoint}/openai/deployments/"
                f"{quote(self.settings.deployment, safe='')}"
                "/chat/completions?"
                + urlencode(
                    {
                        "api-version": (
                            self.settings.api_version
                        )
                    }
                )
            )

        if endpoint.endswith("/v1"):
            return (
                f"{endpoint}/chat/completions"
            )

        return (
            f"{endpoint}/v1/chat/completions"
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": (
                "blackduck-wintermute-ai"
            ),
        }

        if self.settings.provider == "azure":
            if self.settings.api_key:
                headers["api-key"] = (
                    self.settings.api_key
                )
            else:
                headers["Authorization"] = (
                    "Bearer "
                    f"{self.settings.bearer_token}"
                )
        elif self.settings.api_key:
            headers["Authorization"] = (
                f"Bearer {self.settings.api_key}"
            )

        return headers

    def _parse_response(
        self,
        content: bytes,
        headers: Any,
        attempts: int,
    ) -> ModelResponse:
        try:
            payload = json.loads(
                content.decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise AIProviderError(
                "invalid_response",
                "AI endpoint returned invalid JSON",
                attempts=attempts,
            ) from error

        if not isinstance(payload, dict):
            raise AIProviderError(
                "invalid_response",
                "AI response must be an object",
                attempts=attempts,
            )

        usage = self._usage(payload)
        choices = payload.get("choices")

        if (
            not isinstance(choices, list)
            or not choices
            or not isinstance(
                choices[0],
                dict,
            )
        ):
            raise AIProviderError(
                "invalid_response",
                "AI response has no choice",
                attempts=attempts,
                usage=usage,
            )

        choice = choices[0]
        message = choice.get("message")

        if not isinstance(message, dict):
            raise AIProviderError(
                "invalid_response",
                "AI response has no message",
                attempts=attempts,
                usage=usage,
            )

        response_text = message.get(
            "content"
        )

        if (
            not isinstance(response_text, str)
            or not response_text.strip()
        ):
            finish_reason = str(
                choice.get("finish_reason")
                or "unknown"
            )
            raise AIProviderError(
                "empty_response",
                "AI response content is empty; "
                f"finish_reason={finish_reason}",
                attempts=attempts,
                usage=usage,
            )

        request_id = str(
            payload.get("id")
            or self._header(
                headers,
                "x-request-id",
            )
            or ""
        )

        return ModelResponse(
            content=response_text.strip(),
            usage=usage,
            request_id=request_id,
        )

    @staticmethod
    def _usage(
        payload: dict[str, Any],
    ) -> ModelUsage:
        usage = payload.get("usage")
        usage = (
            usage
            if isinstance(usage, dict)
            else {}
        )
        prompt_details = usage.get(
            "prompt_tokens_details"
        )
        prompt_details = (
            prompt_details
            if isinstance(
                prompt_details,
                dict,
            )
            else {}
        )
        completion_details = usage.get(
            "completion_tokens_details"
        )
        completion_details = (
            completion_details
            if isinstance(
                completion_details,
                dict,
            )
            else {}
        )

        return ModelUsage(
            input_tokens=int(
                usage.get(
                    "prompt_tokens"
                )
                or usage.get(
                    "input_tokens"
                )
                or 0
            ),
            output_tokens=int(
                usage.get(
                    "completion_tokens"
                )
                or usage.get(
                    "output_tokens"
                )
                or 0
            ),
            cached_input_tokens=int(
                prompt_details.get(
                    "cached_tokens"
                )
                or 0
            ),
            reasoning_tokens=int(
                completion_details.get(
                    "reasoning_tokens"
                )
                or 0
            ),
        )

    def _before_request(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._prune_failures(now)

            if (
                len(self._failures)
                >= self.settings
                .circuit_breaker_threshold
            ):
                raise AIProviderError(
                    "circuit_open",
                    "AI circuit breaker is open",
                    attempts=0,
                )

            scheduled = max(
                now,
                self._next_request_at,
            )
            delay = max(
                0.0,
                scheduled - now,
            )
            self._next_request_at = (
                scheduled
                + self.settings
                .request_interval_seconds
            )

        if delay:
            self._sleeper(delay)

    def _record_failure(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._prune_failures(now)
            self._failures.append(now)

    def _record_success(self) -> None:
        with self._lock:
            self._failures.clear()

    def _prune_failures(
        self,
        now: float,
    ) -> None:
        boundary = (
            now
            - self.settings
            .circuit_breaker_window_seconds
        )

        while (
            self._failures
            and self._failures[0]
            < boundary
        ):
            self._failures.popleft()

    def _retry(
        self,
        attempt: int,
        headers: Any,
    ) -> None:
        retry_after = self._header(
            headers,
            "Retry-After",
        )

        if retry_after:
            try:
                delay = max(
                    0.0,
                    float(retry_after),
                )
            except ValueError:
                delay = (
                    self.settings
                    .retry_delay_seconds
                    * (attempt + 1)
                )
        else:
            delay = (
                self.settings
                .retry_delay_seconds
                * (attempt + 1)
            )

        self._sleeper(delay)

    def _redact(self, value: str) -> str:
        rendered = str(value)

        for secret in (
            self.settings.api_key,
            self.settings.bearer_token,
        ):
            if secret:
                rendered = rendered.replace(
                    secret,
                    "[REDACTED]",
                )

        return rendered

    @staticmethod
    def _header(
        headers: Any,
        name: str,
    ) -> str:
        if not hasattr(headers, "get"):
            return ""

        return str(
            headers.get(name)
            or headers.get(
                name.casefold()
            )
            or ""
        )
