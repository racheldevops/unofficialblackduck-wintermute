from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from wintermute.blackduck.actions.models import (
    ActionTarget,
    BlackDuckAction,
    utc_now,
    utc_text,
)


def direct_value(
    value: dict[str, Any],
    names: Iterable[str],
) -> Any:
    wanted = {
        str(name).casefold()
        for name in names
    }

    for key, item in value.items():
        if str(key).casefold() in wanted:
            return item

    return None


def text_value(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    if isinstance(value, (int, float, bool)):
        return str(value)

    return ""


def remediation_state(
    payload: dict[str, Any],
    *,
    ownership_marker: str,
) -> dict[str, Any]:
    status = text_value(
        direct_value(
            payload,
            (
                "remediationStatus",
                "remediation_status",
                "status",
            ),
        )
    ).upper()
    comment = text_value(
        direct_value(
            payload,
            (
                "comment",
                "remediationComment",
                "remediation_comment",
            ),
        )
    )

    return {
        "remediation_status": status,
        "comment": comment,
        "owner": (
            ownership_marker
            if (
                ownership_marker
                and ownership_marker in comment
            )
            else ""
        ),
    }


class VulnerabilityRemediationHandler:
    kind = "vulnerability-remediation.set"

    def __init__(
        self,
        read_client: Any,
        write_client: Any | None = None,
        *,
        preserve_existing_decisions: bool = True,
        allowed_statuses: Iterable[str] = (
            "PATCHED",
        ),
        unreviewed_statuses: Iterable[str] = (
            "",
            "NEW",
            "NOT_REVIEWED",
        ),
    ) -> None:
        self.read_client = read_client
        self.write_client = (
            write_client or read_client
        )
        self.preserve_existing_decisions = (
            preserve_existing_decisions
        )
        self.allowed_statuses = {
            str(value).strip().upper()
            for value in allowed_statuses
            if str(value).strip()
        }
        self.unreviewed_statuses = {
            str(value).strip().upper()
            for value in unreviewed_statuses
        }

        if not self.allowed_statuses:
            raise ValueError(
                "At least one remediation status "
                "must be allowed"
            )

    def read_target_state(
        self,
        target: ActionTarget,
        *,
        ownership_marker: str,
    ) -> dict[str, Any]:
        self._validate_target(target)
        payload = self.read_client.get(
            target.resource_href
        )

        return remediation_state(
            payload,
            ownership_marker=ownership_marker,
        )

    def read_state(
        self,
        action: BlackDuckAction,
    ) -> dict[str, Any]:
        self._validate_action(action)

        return self.read_target_state(
            action.target,
            ownership_marker=(
                action.ownership.marker
            ),
        )

    def is_satisfied(
        self,
        action: BlackDuckAction,
        state: dict[str, Any],
    ) -> bool:
        return (
            str(
                state.get(
                    "remediation_status"
                )
                or ""
            ).upper()
            == self._desired_status(action)
        )

    def conflict_reason(
        self,
        action: BlackDuckAction,
        state: dict[str, Any],
    ) -> str:
        preserve = bool(
            action.desired.get(
                "preserve_existing_decisions",
                self.preserve_existing_decisions,
            )
        )

        if not preserve:
            return ""

        if (
            str(state.get("owner") or "")
            == action.ownership.marker
        ):
            return ""

        status = str(
            state.get(
                "remediation_status"
            )
            or ""
        ).upper()
        comment = str(
            state.get("comment") or ""
        ).strip()

        if status not in self.unreviewed_statuses:
            return (
                "Existing remediation status is not "
                "owned by this producer"
            )

        if comment:
            return (
                "Existing remediation comment is not "
                "owned by this producer"
            )

        return ""

    def apply(
        self,
        action: BlackDuckAction,
        state: dict[str, Any],
    ) -> None:
        self._validate_action(action)
        status = self._desired_status(action)
        previous = str(
            state.get(
                "remediation_status"
            )
            or "UNSET"
        )
        marker = action.ownership.marker
        timestamp = utc_text(utc_now())
        evidence = str(
            action.desired.get("comment") or ""
        ).strip()
        comment = (
            f"[{marker}] Wintermute changed remediation "
            f"status from {previous} to {status} at "
            f"{timestamp}."
        )

        if evidence:
            comment = f"{comment} {evidence}"

        if len(comment) > 4000:
            raise ValueError(
                "Remediation comment exceeds 4000 "
                "characters"
            )

        media_type = str(
            action.target.identifiers.get(
                "media_type"
            )
            or "application/json"
        )
        put_json = getattr(
            self.write_client,
            "put_json",
            None,
        )

        if callable(put_json):
            put_json(
                action.target.resource_href,
                {
                    "remediationStatus": status,
                    "comment": comment,
                },
                media_type=media_type,
            )
            return

        self.write_client.request(
            "PUT",
            action.target.resource_href,
            body={
                "remediationStatus": status,
                "comment": comment,
            },
        )

    def _desired_status(
        self,
        action: BlackDuckAction,
    ) -> str:
        status = str(
            action.desired.get(
                "remediation_status"
            )
            or ""
        ).strip().upper()

        if status not in self.allowed_statuses:
            raise ValueError(
                f"Remediation status is not allowed: "
                f"{status!r}"
            )

        return status

    def _validate_action(
        self,
        action: BlackDuckAction,
    ) -> None:
        if action.kind != self.kind:
            raise ValueError(
                f"Unsupported action kind: "
                f"{action.kind}"
            )

        self._validate_target(action.target)

    @staticmethod
    def _validate_target(
        target: ActionTarget,
    ) -> None:
        if (
            target.resource_type
            != "vulnerability-remediation"
        ):
            raise ValueError(
                "Target is not a vulnerability "
                "remediation resource"
            )

        resource = urlsplit(
            target.resource_href
        )
        project_version = urlsplit(
            target.project_version_href
        )
        project_prefix = (
            project_version.path.rstrip("/")
            + "/components/"
        )

        if (
            resource.scheme.casefold()
            != project_version.scheme.casefold()
            or resource.netloc.casefold()
            != project_version.netloc.casefold()
            or resource.query
            or resource.fragment
            or not resource.path.startswith(
                project_prefix
            )
            or not resource.path.rstrip("/").endswith(
                "/remediation"
            )
        ):
            raise ValueError(
                "Remediation URL is outside the "
                "project-version component scope"
            )
