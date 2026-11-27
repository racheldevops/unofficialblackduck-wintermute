from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlsplit


def environment_text(
    environment: Mapping[str, str],
    name: str,
    default: str = "",
) -> str:
    return str(
        environment.get(name, default)
        or default
    ).strip()


def environment_bool(
    environment: Mapping[str, str],
    name: str,
    default: bool,
) -> bool:
    value = environment_text(
        environment,
        name,
    ).casefold()

    if not value:
        return default

    if value in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return True

    if value in {
        "0",
        "false",
        "no",
        "off",
    }:
        return False

    raise ValueError(
        f"{name} must be boolean"
    )


def environment_int(
    environment: Mapping[str, str],
    name: str,
    default: int,
) -> int:
    value = environment_text(
        environment,
        name,
    )

    if not value:
        return default

    try:
        return int(value)
    except ValueError as error:
        raise ValueError(
            f"{name} must be an integer"
        ) from error


def environment_float(
    environment: Mapping[str, str],
    name: str,
    default: float,
) -> float:
    value = environment_text(
        environment,
        name,
    )

    if not value:
        return default

    try:
        return float(value)
    except ValueError as error:
        raise ValueError(
            f"{name} must be numeric"
        ) from error


def is_loopback_url(value: str) -> bool:
    host = (
        urlsplit(value).hostname or ""
    ).casefold()

    return host in {
        "localhost",
        "127.0.0.1",
        "::1",
    }


@dataclass(frozen=True)
class AISettings:
    provider: str
    model: str
    endpoint: str
    deployment: str = ""
    api_version: str = ""
    api_key: str = field(
        default="",
        repr=False,
    )
    bearer_token: str = field(
        default="",
        repr=False,
    )
    timeout_seconds: float = 60
    retries: int = 2
    retry_delay_seconds: float = 1
    request_interval_seconds: float = 1
    circuit_breaker_threshold: int = 5
    circuit_breaker_window_seconds: float = 60
    max_rounds: int = 3
    max_catalog_files: int = 2000
    max_evidence_files: int = 25
    max_evidence_bytes: int = 256 * 1024
    max_file_bytes: int = 128 * 1024
    max_prompt_bytes: int = 512 * 1024
    max_output_tokens: int = 4000
    initial_evidence_files: int = 8
    allow_source: bool = False
    anonymization_key: str = field(
        default="",
        repr=False,
    )
    input_cost_per_million: float = 0
    cached_input_cost_per_million: float = 0
    output_cost_per_million: float = 0
    reasoning_cost_per_million: float = 0
    insecure: bool = False
    ca_bundle: str | None = None

    @property
    def external(self) -> bool:
        if self.provider == "azure":
            return True

        return not is_loopback_url(
            self.endpoint
        )

    def validate(self) -> None:
        if self.provider not in {
            "azure",
            "vllm",
        }:
            raise ValueError(
                "AI provider must be azure or vllm"
            )

        if not self.model:
            raise ValueError(
                "AI model must not be empty"
            )

        parsed = urlsplit(self.endpoint)

        if (
            parsed.scheme.casefold()
            not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError(
                "AI endpoint is invalid"
            )

        if (
            parsed.scheme.casefold() == "http"
            and not is_loopback_url(
                self.endpoint
            )
        ):
            raise ValueError(
                "HTTP AI endpoints are restricted "
                "to loopback addresses"
            )

        if self.provider == "azure":
            if not self.deployment:
                raise ValueError(
                    "Azure OpenAI deployment is required"
                )

            if not self.api_version:
                raise ValueError(
                    "Azure OpenAI API version is required"
                )

            if not (
                self.api_key
                or self.bearer_token
            ):
                raise ValueError(
                    "Azure OpenAI authentication "
                    "is required"
                )

        for field_name in (
            "timeout_seconds",
            "request_interval_seconds",
            "circuit_breaker_window_seconds",
        ):
            if getattr(self, field_name) <= 0:
                raise ValueError(
                    f"{field_name} must be positive"
                )

        if self.retries < 0:
            raise ValueError(
                "retries cannot be negative"
            )

        for field_name in (
            "circuit_breaker_threshold",
            "max_rounds",
            "max_catalog_files",
            "max_evidence_files",
            "max_evidence_bytes",
            "max_file_bytes",
            "max_prompt_bytes",
            "max_output_tokens",
            "initial_evidence_files",
        ):
            if getattr(self, field_name) < 1:
                raise ValueError(
                    f"{field_name} must be positive"
                )

        if (
            self.initial_evidence_files
            > self.max_evidence_files
        ):
            raise ValueError(
                "initial_evidence_files exceeds "
                "max_evidence_files"
            )

        if self.insecure and self.ca_bundle:
            raise ValueError(
                "Use insecure mode or a CA bundle, "
                "not both"
            )

        if self.external:
            if not self.allow_source:
                raise ValueError(
                    "External AI source transmission "
                    "requires WINTERMUTE_AI_ALLOW_SOURCE=true"
                )

            if not self.anonymization_key:
                raise ValueError(
                    "External AI source transmission "
                    "requires "
                    "WINTERMUTE_AI_ANONYMIZATION_KEY"
                )

        for field_name in (
            "input_cost_per_million",
            "cached_input_cost_per_million",
            "output_cost_per_million",
            "reasoning_cost_per_million",
        ):
            if getattr(self, field_name) < 0:
                raise ValueError(
                    f"{field_name} cannot be negative"
                )


def load_ai_settings(
    *,
    environment: (
        Mapping[str, str] | None
    ) = None,
    provider: str = "",
    model: str = "",
    insecure: bool = False,
    ca_bundle: str | None = None,
) -> AISettings:
    selected = (
        os.environ
        if environment is None
        else environment
    )
    selected_provider = (
        provider
        or environment_text(
            selected,
            "WINTERMUTE_AI_PROVIDER",
            "vllm",
        )
    ).casefold()

    if selected_provider == "azure":
        endpoint = environment_text(
            selected,
            "AZURE_OPENAI_ENDPOINT",
        )
        deployment = environment_text(
            selected,
            "AZURE_OPENAI_DEPLOYMENT",
        )
        selected_model = (
            model
            or environment_text(
                selected,
                "WINTERMUTE_AI_MODEL",
                deployment,
            )
        )
        api_version = environment_text(
            selected,
            "AZURE_OPENAI_API_VERSION",
            "2024-10-21",
        )
        api_key = environment_text(
            selected,
            "AZURE_OPENAI_API_KEY",
        )
        bearer_token = environment_text(
            selected,
            "AZURE_OPENAI_BEARER_TOKEN",
        )
    elif selected_provider == "vllm":
        endpoint = environment_text(
            selected,
            "VLLM_BASE_URL",
            "http://127.0.0.1:8000/v1",
        )
        deployment = ""
        selected_model = (
            model
            or environment_text(
                selected,
                "VLLM_MODEL",
            )
            or environment_text(
                selected,
                "WINTERMUTE_AI_MODEL",
            )
        )
        api_version = ""
        api_key = environment_text(
            selected,
            "VLLM_API_KEY",
        )
        bearer_token = ""
    else:
        raise ValueError(
            "WINTERMUTE_AI_PROVIDER must be "
            "azure or vllm"
        )

    settings = AISettings(
        provider=selected_provider,
        model=selected_model,
        endpoint=endpoint,
        deployment=deployment,
        api_version=api_version,
        api_key=api_key,
        bearer_token=bearer_token,
        timeout_seconds=environment_float(
            selected,
            "WINTERMUTE_AI_TIMEOUT_SECONDS",
            60,
        ),
        retries=environment_int(
            selected,
            "WINTERMUTE_AI_RETRIES",
            2,
        ),
        retry_delay_seconds=environment_float(
            selected,
            "WINTERMUTE_AI_RETRY_DELAY_SECONDS",
            1,
        ),
        request_interval_seconds=environment_float(
            selected,
            "WINTERMUTE_AI_REQUEST_INTERVAL_SECONDS",
            1,
        ),
        circuit_breaker_threshold=environment_int(
            selected,
            "WINTERMUTE_AI_CIRCUIT_BREAKER_THRESHOLD",
            5,
        ),
        circuit_breaker_window_seconds=environment_float(
            selected,
            "WINTERMUTE_AI_CIRCUIT_BREAKER_WINDOW_SECONDS",
            60,
        ),
        max_rounds=environment_int(
            selected,
            "WINTERMUTE_AI_MAX_ROUNDS",
            3,
        ),
        max_catalog_files=environment_int(
            selected,
            "WINTERMUTE_AI_MAX_CATALOG_FILES",
            2000,
        ),
        max_evidence_files=environment_int(
            selected,
            "WINTERMUTE_AI_MAX_EVIDENCE_FILES",
            25,
        ),
        max_evidence_bytes=environment_int(
            selected,
            "WINTERMUTE_AI_MAX_EVIDENCE_BYTES",
            256 * 1024,
        ),
        max_file_bytes=environment_int(
            selected,
            "WINTERMUTE_AI_MAX_FILE_BYTES",
            128 * 1024,
        ),
        max_prompt_bytes=environment_int(
            selected,
            "WINTERMUTE_AI_MAX_PROMPT_BYTES",
            512 * 1024,
        ),
        max_output_tokens=environment_int(
            selected,
            "WINTERMUTE_AI_MAX_OUTPUT_TOKENS",
            4000,
        ),
        initial_evidence_files=environment_int(
            selected,
            "WINTERMUTE_AI_INITIAL_EVIDENCE_FILES",
            8,
        ),
        allow_source=environment_bool(
            selected,
            "WINTERMUTE_AI_ALLOW_SOURCE",
            False,
        ),
        anonymization_key=environment_text(
            selected,
            "WINTERMUTE_AI_ANONYMIZATION_KEY",
        ),
        input_cost_per_million=environment_float(
            selected,
            "WINTERMUTE_AI_INPUT_COST_PER_MILLION",
            0,
        ),
        cached_input_cost_per_million=(
            environment_float(
                selected,
                "WINTERMUTE_AI_CACHED_INPUT_COST_PER_MILLION",
                0,
            )
        ),
        output_cost_per_million=environment_float(
            selected,
            "WINTERMUTE_AI_OUTPUT_COST_PER_MILLION",
            0,
        ),
        reasoning_cost_per_million=environment_float(
            selected,
            "WINTERMUTE_AI_REASONING_COST_PER_MILLION",
            0,
        ),
        insecure=insecure,
        ca_bundle=ca_bundle,
    )
    settings.validate()
    return settings
