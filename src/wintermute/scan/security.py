from __future__ import annotations

import json
import os
import platform
import re
import ssl
from typing import Any
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)


PLATFORMS = {"linux/amd64", "linux/arm64"}
MACHINE_PLATFORMS = {
    "amd64": "linux/amd64",
    "x86_64": "linux/amd64",
    "arm64": "linux/arm64",
    "aarch64": "linux/arm64",
}


def redact_text(value: str) -> str:
    rendered = str(value)
    secrets = {
        secret
        for name, secret in os.environ.items()
        if secret
        and any(
            marker in name.upper()
            for marker in ("TOKEN", "PASSWORD", "SECRET", "API_KEY")
        )
    }
    for secret in sorted(secrets, key=len, reverse=True):
        rendered = rendered.replace(secret, "[REDACTED]")
    return rendered


def redact_payload(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact_payload(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_payload(nested) for nested in value]
    return value


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        raise RuntimeError(
            "Authenticated HTTP redirect refused before forwarding credentials"
        )


def secure_urlopen(
    request: Request,
    *,
    timeout: float,
    context: ssl.SSLContext | None = None,
):
    parsed = urlsplit(request.full_url)
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("Authenticated request requires a credential-free HTTPS URL")

    return build_opener(
        HTTPSHandler(context=context),
        RejectRedirects(),
    ).open(request, timeout=timeout)


def sha256_digest(value: str) -> str:
    selected = str(value or "").strip().removeprefix("sha256:").casefold()
    if re.fullmatch(r"[0-9a-f]{64}", selected) is None:
        raise ValueError("Expected Bridge SHA-256 is invalid")
    return selected


def bridge_checksums(value: str) -> str | dict[str, str]:
    selected = str(value or "").strip()
    if not selected.startswith("{"):
        return sha256_digest(selected)

    def unique_object(pairs):
        result = {}
        for key, nested in pairs:
            if key in result:
                raise ValueError("Duplicate Bridge checksum platform")
            result[key] = nested
        return result

    try:
        payload = json.loads(selected, object_pairs_hook=unique_object)
    except json.JSONDecodeError as error:
        raise ValueError("Bridge checksum map is invalid JSON") from error

    if not isinstance(payload, dict) or set(payload) != PLATFORMS:
        raise ValueError(
            "Bridge checksum map must contain linux/amd64 and linux/arm64"
        )
    if not all(isinstance(digest, str) for digest in payload.values()):
        raise ValueError("Bridge platform checksums must be strings")
    return {
        name: sha256_digest(payload[name])
        for name in sorted(payload)
    }


def resolve_bridge_checksum(value: str, *, machine: str | None = None) -> str:
    selected = bridge_checksums(value)
    if isinstance(selected, str):
        return selected

    architecture = str(machine or platform.machine()).casefold()
    image_platform = MACHINE_PLATFORMS.get(architecture)
    if image_platform is None:
        raise ValueError(f"Unsupported Bridge runtime architecture: {architecture}")
    return selected[image_platform]
