from __future__ import annotations

import inspect

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from wintermute.blackduck.inventory import (
    version_name,
    version_updated,
)
from wintermute.blackduck.resources import (
    canonical_href,
    first_value_by_key,
    get_link,
    get_self_href,
    sha256_hex,
)


CandidateCounter = Callable[
    [Any, dict[str, Any], str],
    int,
]
PolicyCounter = Callable[
    [Any, str, Any],
    tuple[int, int, str, str],
]


@dataclass(frozen=True)
class CandidateDiscoveryCriteria:
    candidate_mode: str = "vulnerable-only"
    policy_name: str = ""
    policy_rule_id: str = ""
    skip_policy_rules: bool = False

    def __post_init__(self) -> None:
        if self.candidate_mode not in {
            "vulnerable-only",
            "policy-only",
            "both",
        }:
            raise ValueError(
                "candidate_mode must be vulnerable-only, "
                "policy-only, or both"
            )

        if (
            self.skip_policy_rules
            and (
                self.policy_name
                or self.policy_rule_id
            )
        ):
            raise ValueError(
                "skip_policy_rules cannot be used "
                "with policy filters"
            )


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def candidate_key(
    project: str,
    project_version: str,
    project_version_href: str,
) -> str:
    return "|".join(
        [
            project,
            project_version,
            canonical_href(project_version_href),
        ]
    )


def candidate_external_id(
    project: str,
    project_version: str,
    project_version_href: str,
) -> str:
    return sha256_hex(
        candidate_key(
            project,
            project_version,
            project_version_href,
        )
    )


def stable_candidate(
    row: dict[str, str],
) -> dict[str, str]:
    return {
        key: str(row.get(key, ""))
        for key in (
            "project",
            "project_version",
            "project_phase",
            "project_updated",
            "project_href",
            "project_version_href",
            "candidate_reason",
            "candidate_policy_name",
            "candidate_policy_rule_href",
            "candidate_vulnerable_component_count",
            "candidate_policy_violation_count",
            "candidate_security_violation_count",
            "candidate_key",
            "candidate_external_id",
        )
    }


def candidate_cache_settings(
    settings: Any,
) -> dict[str, Any]:
    return {
        "candidate_mode": str(
            getattr(
                settings,
                "candidate_mode",
                "",
            )
            or ""
        ),
        "policy_name": str(
            getattr(settings, "policy_name", "")
            or ""
        ),
        "policy_rule_id": str(
            getattr(
                settings,
                "policy_rule_id",
                "",
            )
            or ""
        ),
        "skip_policy_rules": bool(
            getattr(
                settings,
                "skip_policy_rules",
                False,
            )
        ),
    }


def count_vulnerable_components(
    client: Any,
    version: dict[str, Any],
    project_version_href: str,
) -> int:
    if not project_version_href:
        return 0

    direct_url = (
        f"{canonical_href(project_version_href)}"
        "/vulnerable-bom-components"
    )

    try:
        return client.count_items(direct_url)
    except RuntimeError as direct_error:
        if getattr(client, "debug", False):
            import sys

            print(
                f"Direct vulnerable component check failed for "
                f"{project_version_href}: {direct_error}",
                file=sys.stderr,
            )

    linked_url = get_link(
        version,
        (
            "vulnerable-bom-components",
            "vulnerableBomComponents",
            "vulnerable-components",
        ),
    )

    if not linked_url:
        try:
            refreshed_version = client.get(
                project_version_href
            )
            linked_url = get_link(
                refreshed_version,
                (
                    "vulnerable-bom-components",
                    "vulnerableBomComponents",
                    "vulnerable-components",
                ),
            )
        except RuntimeError:
            linked_url = ""

    if not linked_url:
        return 0

    try:
        return client.count_items(linked_url)
    except RuntimeError:
        return 0


def count_policy_violations(
    client: Any,
    project_version_href: str,
    settings: Any,
) -> tuple[int, int, str, str]:
    if not project_version_href:
        return 0, 0, "", ""

    candidate_mode = str(
        getattr(
            settings,
            "candidate_mode",
            "vulnerable-only",
        )
    )
    policy_name_filter = str(
        getattr(settings, "policy_name", "")
        or ""
    )
    policy_rule_filter = str(
        getattr(settings, "policy_rule_id", "")
        or ""
    )
    skip_policy_rules = bool(
        getattr(
            settings,
            "skip_policy_rules",
            False,
        )
    )
    need_rule_details = (
        not skip_policy_rules
        and (
            bool(
                policy_name_filter
                or policy_rule_filter
            )
            or candidate_mode == "both"
        )
    )
    component_limit = (
        25 if need_rule_details else 1
    )

    try:
        policy_count, components = (
            client.collection_count_and_items(
                (
                    f"{canonical_href(project_version_href)}"
                    "/components"
                ),
                params={
                    "filter": (
                        "policyStatus:IN_VIOLATION"
                    )
                },
                limit=component_limit,
            )
        )
    except RuntimeError:
        return 0, 0, "", ""

    if not need_rule_details:
        return policy_count, 0, "", ""

    security_count = 0
    matched_name = ""
    matched_href = ""

    for component in components[:25]:
        rules_url = get_link(
            component,
            (
                "policy-rules",
                "policyRules",
                "policy-rule",
            ),
        )

        if not rules_url:
            continue

        try:
            _, rules = (
                client.collection_count_and_items(
                    rules_url,
                    limit=25,
                )
            )
        except RuntimeError:
            continue

        for rule in rules[:25]:
            category = str(
                first_value_by_key(
                    rule,
                    (
                        "category",
                        "policyCategory",
                    ),
                )
                or ""
            ).upper()
            name = str(
                first_value_by_key(
                    rule,
                    (
                        "name",
                        "policyName",
                        "policyRuleName",
                    ),
                )
                or ""
            )
            href = canonical_href(
                get_self_href(rule)
                or get_link(rule, ("self",))
            )

            if category == "SECURITY":
                security_count += 1

            if (
                policy_name_filter
                and name == policy_name_filter
            ):
                matched_name = name
                matched_href = href

            if (
                policy_rule_filter
                and policy_rule_filter in href
            ):
                matched_name = name
                matched_href = href

    return (
        policy_count,
        security_count,
        matched_name,
        matched_href,
    )


def build_candidate_row(
    project: dict[str, Any],
    version: dict[str, Any],
    settings: Any,
    *,
    vulnerable_count: int,
    policy_count: int,
    security_count: int,
    policy_name: str,
    policy_href: str,
) -> dict[str, str]:
    project_name = str(
        project.get("name") or ""
    )
    project_version = version_name(version)
    project_href = canonical_href(
        get_self_href(project)
    )
    project_version_href = canonical_href(
        get_self_href(version)
    )
    key = candidate_key(
        project_name,
        project_version,
        project_version_href,
    )
    reasons: list[str] = []

    if vulnerable_count > 0:
        reasons.append(
            "vulnerable-bom-components"
        )

    if policy_count > 0:
        reasons.append("policy-violation")

    if security_count > 0:
        reasons.append(
            "security-policy-violation"
        )

    requested_policy_name = str(
        getattr(settings, "policy_name", "")
        or ""
    )
    requested_policy_rule = str(
        getattr(settings, "policy_rule_id", "")
        or ""
    )

    if (
        requested_policy_name
        or requested_policy_rule
    ):
        if policy_name or policy_href:
            reasons.append(
                "requested-policy-match"
            )
        else:
            reasons = []

    return {
        "project": project_name,
        "project_version": project_version,
        "project_phase": str(
            version.get("phase") or ""
        ),
        "project_updated": version_updated(version),
        "project_href": project_href,
        "project_version_href": (
            project_version_href
        ),
        "candidate_reason": ";".join(
            sorted(set(reasons))
        ),
        "candidate_policy_name": (
            policy_name
            or requested_policy_name
        ),
        "candidate_policy_rule_href": (
            policy_href
        ),
        "candidate_vulnerable_component_count": (
            str(vulnerable_count)
        ),
        "candidate_policy_violation_count": (
            str(policy_count)
        ),
        "candidate_security_violation_count": (
            str(security_count)
        ),
        "candidate_detected_at": now_iso(),
        "cache_entry_status": "ok",
        "cache_reuse_reason": "fresh-scan",
        "scan_error": "",
        "candidate_key": key,
        "candidate_external_id": sha256_hex(key),
    }


def invoke_compatible_counter(
    operation: Any,
    positional: tuple[Any, ...],
    keyword: dict[str, Any],
) -> Any:
    try:
        signature = inspect.signature(operation)
    except (TypeError, ValueError):
        return operation(*positional)

    try:
        signature.bind(*positional)
    except TypeError:
        signature.bind(**keyword)
        return operation(**keyword)

    return operation(*positional)

def scan_candidate(
    client: Any,
    project: dict[str, Any],
    version: dict[str, Any],
    settings: Any,
    *,
    vulnerable_counter: CandidateCounter | None = None,
    policy_counter: PolicyCounter | None = None,
) -> dict[str, str]:
    vulnerable_counter = (
        vulnerable_counter
        or count_vulnerable_components
    )
    policy_counter = (
        policy_counter
        or count_policy_violations
    )
    project_version_href = canonical_href(
        get_self_href(version)
    )
    candidate_mode = str(
        getattr(
            settings,
            "candidate_mode",
            "vulnerable-only",
        )
    )
    vulnerable_count = 0
    policy_count = 0
    security_count = 0
    policy_name = ""
    policy_href = ""

    if candidate_mode in {
        "vulnerable-only",
        "both",
    }:
        vulnerable_count = invoke_compatible_counter(
            vulnerable_counter,
            (
                client,
                version,
                project_version_href,
            ),
            {
                "client": client,
                "version": version,
                "project_version_href": (
                    project_version_href
                ),
            },
        )

    if candidate_mode in {
        "policy-only",
        "both",
    }:
        (
            policy_count,
            security_count,
            policy_name,
            policy_href,
        ) = invoke_compatible_counter(
            policy_counter,
            (
                client,
                project_version_href,
                settings,
            ),
            {
                "client": client,
                "project_version_href": (
                    project_version_href
                ),
                "settings": settings,
            },
        )

    return build_candidate_row(
        project,
        version,
        settings,
        vulnerable_count=vulnerable_count,
        policy_count=policy_count,
        security_count=security_count,
        policy_name=policy_name,
        policy_href=policy_href,
    )
