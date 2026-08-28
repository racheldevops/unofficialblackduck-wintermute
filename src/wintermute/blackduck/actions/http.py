from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from wintermute.blackduck.actions.models import (
    belongs_to_instance,
)


MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class BlackDuckActionHttpError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        uncertain: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.uncertain = uncertain


@dataclass(frozen=True)
class ActionHttpResponse:
    status_code: int
    payload: dict[str, Any]


class BlackDuckActionHttpClient:
    def __init__(
        self,
        client: Any,
    ) -> None:
        self.client = client
        self.base_url = str(
            client.base_url
        ).rstrip("/")

    def put_json(
        self,
        url: str,
        body: dict[str, Any],
        *,
        media_type: str = "application/json",
    ) -> ActionHttpResponse:
        if (
            not media_type.startswith("application/")
            or "\r" in media_type
            or "\n" in media_type
            or len(media_type) > 256
        ):
            raise ValueError(
                "Invalid Black Duck media type"
            )

        return self._request(
            "PUT",
            url,
            body=body,
            headers={
                "Accept": media_type,
                "Content-Type": media_type,
            },
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> ActionHttpResponse:
        if not belongs_to_instance(
            self.base_url,
            url,
        ):
            raise ValueError(
                "Action URL belongs to another "
                "Black Duck instance"
            )

        token = self.client.bearer_token

        if not token:
            raise BlackDuckActionHttpError(
                "Black Duck client is not authenticated"
            )

        data = json.dumps(
            body,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        request_headers = {
            **headers,
            "Authorization": f"Bearer {token}",
        }
        request = Request(
            url,
            data=data,
            headers=request_headers,
            method=method,
        )
        permit = (
            self.client.request_control
            .before_request(
                method,
                url,
            )
        )

        try:
            with urlopen(
                request,
                timeout=self.client.timeout,
                context=self.client.ssl_context,
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
                final_url = str(
                    getattr(
                        response,
                        "url",
                        "",
                    )
                    or getattr(
                        response,
                        "geturl",
                        lambda: url,
                    )()
                    or url
                )

            if not belongs_to_instance(
                self.base_url,
                final_url,
            ):
                raise BlackDuckActionHttpError(
                    "Black Duck redirected the action "
                    "to another instance",
                    status_code=status,
                    uncertain=True,
                )

            if len(content) > MAX_RESPONSE_BYTES:
                raise BlackDuckActionHttpError(
                    "Black Duck action response exceeded "
                    "the maximum size",
                    status_code=status,
                    uncertain=True,
                )

            self.client.request_control.record_success()

            if not content:
                payload: dict[str, Any] = {}
            else:
                try:
                    decoded = json.loads(
                        content.decode("utf-8")
                    )
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                ) as error:
                    raise BlackDuckActionHttpError(
                        "Black Duck action returned "
                        "invalid JSON",
                        status_code=status,
                        uncertain=True,
                    ) from error

                if not isinstance(decoded, dict):
                    raise BlackDuckActionHttpError(
                        "Black Duck action returned a "
                        "non-object response",
                        status_code=status,
                        uncertain=True,
                    )

                payload = decoded

            return ActionHttpResponse(
                status_code=status,
                payload=payload,
            )

        except HTTPError as error:
            body_text = error.read(4000).decode(
                "utf-8",
                errors="replace",
            )
            body_text = body_text.replace(
                token,
                "[REDACTED]",
            )
            _, opened = (
                self.client.request_control
                .record_server_failure(
                    error.code,
                    url,
                    context=permit.context,
                )
            )

            if opened:
                raise (
                    self.client.request_control
                    .circuit_error()
                ) from error

            raise BlackDuckActionHttpError(
                f"{method} action failed: HTTP "
                f"{error.code} {error.reason}: "
                f"{body_text}",
                status_code=error.code,
                uncertain=False,
            ) from error

        except (
            URLError,
            TimeoutError,
            OSError,
        ) as error:
            raise BlackDuckActionHttpError(
                f"{method} action failed: "
                f"{type(error).__name__}: {error}",
                uncertain=True,
            ) from error
