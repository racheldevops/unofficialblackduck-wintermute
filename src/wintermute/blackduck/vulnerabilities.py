from __future__ import annotations

import json
from typing import Any, Iterable

from wintermute.blackduck.resources import (
    boolish,
    first_value_by_key,
    get_link,
    get_self_href,
    to_float,
)


DEFAULT_VULNERABILITY_ID_FIELDS = (
    "vulnerabilityName",
    "vulnerabilityId",
    "vulnerabilityExternalId",
    "externalId",
    "cveId",
    "cve",
    "bdsaId",
    "name",
    "id",
)

DEFAULT_SEVERITY_FIELDS = (
    "severity",
    "vulnerabilitySeverity",
    "sourceSeverity",
)

DEFAULT_CVSS_VECTOR_FIELDS = (
    "cvssVector",
    "cvss3Vector",
    "cvss31Vector",
    "cvssV3Vector",
    "cvssV31Vector",
    "cvss2Vector",
    "vector",
)


def vulnerability_identifier(
    value: dict[str, Any],
    id_fields: Iterable[str] = DEFAULT_VULNERABILITY_ID_FIELDS,
) -> str:
    return str(
        first_value_by_key(value, id_fields)
        or "UNKNOWN"
    )


def vulnerability_severity(
    value: dict[str, Any],
    *,
    uppercase: bool = False,
) -> str:
    severity = str(
        first_value_by_key(
            value,
            DEFAULT_SEVERITY_FIELDS,
        )
        or ""
    )

    return severity.upper() if uppercase else severity


def vulnerability_score(
    value: dict[str, Any],
    score_fields: Iterable[str],
) -> float | None:
    return to_float(
        first_value_by_key(value, score_fields)
    )


def vulnerability_cvss_vector(
    value: dict[str, Any],
) -> str:
    return str(
        first_value_by_key(
            value,
            DEFAULT_CVSS_VECTOR_FIELDS,
        )
        or ""
    )


def vulnerability_href(
    value: dict[str, Any],
) -> str:
    return (
        get_link(value, ("self",))
        or get_self_href(value)
    )


def looks_like_vulnerability(
    value: dict[str, Any],
    *,
    score_fields: Iterable[str],
    id_fields: Iterable[str] = DEFAULT_VULNERABILITY_ID_FIELDS,
) -> bool:
    has_id = first_value_by_key(
        value,
        id_fields,
    ) is not None
    has_score = first_value_by_key(
        value,
        score_fields,
    ) is not None
    has_severity = first_value_by_key(
        value,
        DEFAULT_SEVERITY_FIELDS,
    ) is not None

    return has_id and (has_score or has_severity)


def extract_vulnerability_candidates(
    value: Any,
    *,
    score_fields: Iterable[str],
    id_fields: Iterable[str] = DEFAULT_VULNERABILITY_ID_FIELDS,
    dedupe_score_fields: Iterable[str] | None = None,
    dedupe_payload_limit: int = 500,
) -> list[dict[str, Any]]:
    score_fields = tuple(score_fields)
    id_fields = tuple(id_fields)
    dedupe_score_fields = tuple(
        dedupe_score_fields or score_fields
    )
    id_field_names = {
        str(field).lower()
        for field in id_fields
    }
    score_field_names = {
        str(field).lower()
        for field in score_fields
    }
    severity_field_names = {
        field.lower()
        for field in DEFAULT_SEVERITY_FIELDS
    }
    candidates: list[dict[str, Any]] = []

    def direct_value(
        item: dict[str, Any],
        field_names: set[str],
    ) -> Any:
        for key, item_value in item.items():
            if (
                str(key).lower() in field_names
                and item_value not in (None, "")
            ):
                return item_value

        return None

    def is_direct_vulnerability(
        item: dict[str, Any],
    ) -> bool:
        has_id = direct_value(
            item,
            id_field_names,
        ) is not None
        has_score = direct_value(
            item,
            score_field_names,
        ) is not None
        has_severity = direct_value(
            item,
            severity_field_names,
        ) is not None

        return has_id and (has_score or has_severity)

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            nested = item.get("vulnerability")

            if isinstance(nested, dict):
                merged = dict(nested)

                for key, nested_item in item.items():
                    if key != "vulnerability" and key not in merged:
                        merged[key] = nested_item

                if is_direct_vulnerability(merged):
                    candidates.append(merged)

            elif is_direct_vulnerability(item):
                candidates.append(item)

            for key, nested_item in item.items():
                if (
                    key == "vulnerability"
                    and isinstance(nested, dict)
                ):
                    continue

                walk(nested_item)

        elif isinstance(item, list):
            for nested_item in item:
                walk(nested_item)

    walk(value)

    unique: list[dict[str, Any]] = []
    seen: set[str] = set()

    for candidate in candidates:
        key = "|".join(
            [
                vulnerability_identifier(
                    candidate,
                    id_fields,
                ),
                str(
                    first_value_by_key(
                        candidate,
                        dedupe_score_fields,
                    )
                    or ""
                ),
                json.dumps(
                    candidate,
                    sort_keys=True,
                    default=str,
                )[:dedupe_payload_limit],
            ]
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(candidate)

    return unique


def extract_exploit_available(
    value: dict[str, Any],
) -> tuple[bool, str]:
    direct = first_value_by_key(
        value,
        (
            "exploitAvailable",
            "exploit_available",
            "exploitable",
            "hasExploit",
            "exploitability",
            "exploitStatus",
        ),
    )

    if direct not in (None, ""):
        return boolish(direct), str(direct)

    for key, item in value.items():
        key_lower = str(key).lower()

        if (
            "exploit" in key_lower
            and "score" not in key_lower
            and boolish(item)
        ):
            return True, str(item)

    return False, ""


def extract_reachability(
    value: dict[str, Any],
) -> tuple[bool, str, str]:
    direct = first_value_by_key(
        value,
        (
            "reachable",
            "reachability",
            "reachabilityStatus",
            "isReachable",
        ),
    )

    if direct not in (None, ""):
        return boolish(direct), str(direct), "field"

    return False, "", ""
