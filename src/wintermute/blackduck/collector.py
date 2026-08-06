from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from wintermute.blackduck.criteria import (
    CollectionCriteria,
)
from wintermute.blackduck.models import (
    CollectionTarget,
    NormalizedFinding,
)
from wintermute.blackduck.resources import (
    canonical_href,
    first_value_by_key,
    get_link,
    get_self_href,
    iter_hrefs,
    looks_like_resource_url,
    sorted_unique,
)
from wintermute.blackduck.vulnerabilities import (
    extract_exploit_available,
    extract_reachability,
    extract_vulnerability_candidates,
    vulnerability_cvss_vector,
    vulnerability_href,
    vulnerability_identifier,
    vulnerability_score,
    vulnerability_severity,
)
from wintermute.concurrency import (
    DEFAULT_IO_WORKERS,
    MAX_COMPONENT_WORKERS,
    MAX_IO_WORKERS,
    bounded_worker_count,
    ordered_parallel_map,
)


EntityResolver = Callable[
    [Any, CollectionTarget],
    str,
]


@dataclass(frozen=True)
class CollectionFailure:
    target_external_id: str
    project: str
    project_version: str
    project_version_href: str
    stage: str
    error: str
    component: str = ""
    component_href: str = ""


@dataclass(frozen=True)
class TargetCollectionResult:
    target: CollectionTarget
    findings: tuple[NormalizedFinding, ...]
    failures: tuple[CollectionFailure, ...]
    elapsed_seconds: float

    @property
    def status(self) -> str:
        if self.failures and self.findings:
            return "partial"

        if self.failures:
            return "failed"

        return "ok"


@dataclass(frozen=True)
class CollectionRunResult:
    target_results: tuple[
        TargetCollectionResult,
        ...
    ]

    @property
    def findings(self) -> tuple[
        NormalizedFinding,
        ...
    ]:
        findings: list[NormalizedFinding] = []
        seen: set[str] = set()

        for result in self.target_results:
            for finding in result.findings:
                if finding.external_id in seen:
                    continue

                seen.add(finding.external_id)
                findings.append(finding)

        return tuple(findings)

    @property
    def failures(self) -> tuple[
        CollectionFailure,
        ...
    ]:
        return tuple(
            failure
            for result in self.target_results
            for failure in result.failures
        )

    @property
    def succeeded_target_count(self) -> int:
        return sum(
            result.status == "ok"
            for result in self.target_results
        )

    @property
    def partial_target_count(self) -> int:
        return sum(
            result.status == "partial"
            for result in self.target_results
        )

    @property
    def failed_target_count(self) -> int:
        return sum(
            result.status == "failed"
            for result in self.target_results
        )


def get_vulnerable_components(
    client: Any,
    project_version_href: str,
) -> list[dict[str, Any]]:
    direct_url = (
        f"{canonical_href(project_version_href)}"
        "/vulnerable-bom-components"
    )

    try:
        return client.paged_get(direct_url)
    except RuntimeError as direct_error:
        try:
            version = client.get(
                project_version_href
            )
        except RuntimeError:
            raise direct_error

        linked_url = get_link(
            version,
            (
                "vulnerable-bom-components",
                "vulnerableBomComponents",
                "vulnerable-components",
            ),
        )

        if not linked_url:
            raise direct_error

        return client.paged_get(linked_url)


def component_version_href(
    component: dict[str, Any],
) -> str:
    candidates = [
        component.get("componentVersionHref"),
        component.get("componentVersionUrl"),
        component.get("componentVersion"),
    ]

    for candidate in candidates:
        if (
            isinstance(candidate, str)
            and looks_like_resource_url(candidate)
            and "/api/components/" in candidate
            and "/versions/" in candidate
        ):
            return canonical_href(candidate)

        if isinstance(candidate, dict):
            for href in iter_hrefs(candidate):
                if (
                    "/api/components/" in href
                    and "/versions/" in href
                ):
                    return canonical_href(href)

    linked = get_link(
        component,
        (
            "component-version",
            "componentVersion",
            "component_version",
        ),
    )

    if linked:
        return canonical_href(linked)

    for href in iter_hrefs(component):
        if (
            "/api/components/" in href
            and "/versions/" in href
        ):
            return canonical_href(href)

    return ""


def component_details(
    client: Any,
    component: dict[str, Any],
) -> tuple[str, str, str, str]:
    name = str(
        first_value_by_key(
            component,
            (
                "componentName",
                "name",
            ),
        )
        or ""
    )
    version = str(
        first_value_by_key(
            component,
            (
                "componentVersionName",
                "versionName",
            ),
        )
        or ""
    ).strip()
    direct_version = component.get(
        "componentVersion"
    )

    if (
        not version
        and isinstance(
            direct_version,
            (str, int, float),
        )
    ):
        direct_text = str(
            direct_version
        ).strip()

        if not looks_like_resource_url(
            direct_text
        ):
            version = direct_text

    if looks_like_resource_url(version):
        version = ""

    version_href = component_version_href(
        component
    )

    if version_href and not version:
        try:
            version_resource = client.get(
                version_href
            )
        except RuntimeError:
            version_resource = {}
        else:
            version = str(
                version_resource.get("versionName")
                or version_resource.get("name")
                or first_value_by_key(
                    version_resource,
                    (
                        "componentVersionName",
                        "versionName",
                    ),
                )
                or ""
            ).strip()

            if looks_like_resource_url(version):
                version = ""

    bom_component_href = canonical_href(
        get_self_href(component)
    )

    return (
        name,
        version,
        version_href,
        bom_component_href,
    )


def get_policy_rules(
    client: Any,
    component: dict[str, Any],
) -> list[dict[str, Any]]:
    url = get_link(
        component,
        (
            "policy-rules",
            "policyRules",
            "policy-rule",
        ),
    )

    if not url:
        return []

    try:
        return client.paged_get(url)
    except RuntimeError:
        return []


def policy_match(
    client: Any,
    component: dict[str, Any],
    criteria: CollectionCriteria,
) -> tuple[bool, str, str]:
    needs_rules = (
        not criteria.skip_policy_rules
        and (
            bool(
                criteria.policy_name
                or criteria.policy_rule_id
            )
            or criteria.include_policy_rule_details
        )
    )

    if not needs_rules:
        return True, "", ""

    rules = get_policy_rules(
        client,
        component,
    )
    names: list[str] = []
    hrefs: list[str] = []

    for rule in rules:
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

        if name:
            names.append(name)

        if href:
            hrefs.append(href)

        if (
            criteria.policy_name
            and name == criteria.policy_name
        ):
            return True, name, href

        if (
            criteria.policy_rule_id
            and criteria.policy_rule_id in href
        ):
            return True, name, href

    if (
        criteria.policy_name
        or criteria.policy_rule_id
    ):
        return False, "", ""

    return (
        True,
        ";".join(sorted_unique(names)),
        ";".join(sorted_unique(hrefs)),
    )


def collect_component_findings(
    client: Any,
    target: CollectionTarget,
    component: dict[str, Any],
    criteria: CollectionCriteria,
    *,
    entity: str = "",
) -> list[NormalizedFinding]:
    (
        name,
        version,
        version_href,
        bom_component_href,
    ) = component_details(
        client,
        component,
    )
    matched_policy, policy_name, policy_href = (
        policy_match(
            client,
            component,
            criteria,
        )
    )

    if not matched_policy:
        return []

    vulnerabilities_url = get_link(
        component,
        (
            "vulnerabilities",
            "vulnerability",
        ),
    )
    vulnerability_items: list[dict[str, Any]] = []
    score_fields = (
        criteria.score_field,
        "overallScore",
        "baseScore",
        "cvssScore",
    )

    if vulnerabilities_url:
        for item in client.paged_get(
            vulnerabilities_url
        ):
            extracted = (
                extract_vulnerability_candidates(
                    item,
                    score_fields=score_fields,
                    dedupe_score_fields=(
                        criteria.score_field,
                        "overallScore",
                    ),
                )
            )
            vulnerability_items.extend(
                extracted or [item]
            )
    else:
        vulnerability_items.extend(
            extract_vulnerability_candidates(
                component,
                score_fields=score_fields,
                dedupe_score_fields=(
                    criteria.score_field,
                    "overallScore",
                ),
            )
        )

    findings: list[NormalizedFinding] = []

    for vulnerability in vulnerability_items:
        score = vulnerability_score(
            vulnerability,
            score_fields,
        )

        if not criteria.score_passes(score):
            continue

        (
            exploit_available,
            exploitable,
        ) = extract_exploit_available(
            vulnerability
        )

        if (
            criteria.require_exploit_available
            and not exploit_available
        ):
            continue

        (
            reachable,
            reachability,
            reachability_source,
        ) = extract_reachability(
            vulnerability
        )

        if (
            criteria.require_reachable
            and not reachable
        ):
            continue

        if (
            criteria.reachability_mode == "ai"
            and not reachability_source
        ):
            reachability_source = "ai-reserved"

        findings.append(
            NormalizedFinding(
                project_version=(
                    target.project_version
                ),
                component=name,
                component_version=version,
                component_href=(
                    version_href
                    or bom_component_href
                ),
                vulnerability=(
                    vulnerability_identifier(
                        vulnerability
                    )
                ),
                severity=(
                    vulnerability_severity(
                        vulnerability,
                        uppercase=True,
                    )
                ),
                score_field=(
                    criteria.score_field
                ),
                score=score,
                vulnerability_href=(
                    vulnerability_href(
                        vulnerability
                    )
                ),
                cvss_vector=(
                    vulnerability_cvss_vector(
                        vulnerability
                    )
                ),
                exploit_available=(
                    exploit_available
                ),
                exploitable=exploitable,
                reachable=reachable,
                reachability=reachability,
                reachability_source=(
                    reachability_source
                ),
                policy_name=policy_name,
                policy_rule_href=policy_href,
                entity=entity,
                lineage_contexts=(
                    target.lineage_contexts
                ),
                attributes={
                    "bom_component_url": (
                        bom_component_href
                    ),
                    "component_version_href": (
                        version_href
                    ),
                    "component_origin_id": str(
                        first_value_by_key(
                            component,
                            (
                                "componentOriginId",
                                "originId",
                                "externalId",
                            ),
                        )
                        or ""
                    ),
                    "policy_matched": (
                        matched_policy
                    ),
                },
            )
        )

    return findings


def vulnerable_component_identity(
    component: dict[str, Any],
) -> tuple[str, str, str] | None:
    vulnerabilities_url = canonical_href(
        get_link(
            component,
            (
                "vulnerabilities",
                "vulnerability",
            ),
        )
    )

    if not vulnerabilities_url:
        return None

    name = str(
        first_value_by_key(
            component,
            (
                "componentName",
                "name",
            ),
        )
        or ""
    )
    version = str(
        first_value_by_key(
            component,
            (
                "componentVersionName",
                "versionName",
            ),
        )
        or ""
    ).strip()

    if not version or looks_like_resource_url(version):
        version = component_version_href(
            component
        )

    return (
        name,
        version,
        vulnerabilities_url,
    )


def dedupe_vulnerable_components(
    components: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for component in components:
        identity = vulnerable_component_identity(
            component
        )

        if identity is None:
            unique.append(component)
            continue

        if identity in seen:
            continue

        seen.add(identity)
        unique.append(component)

    return unique

def collect_target(
    client: Any,
    target: CollectionTarget,
    criteria: CollectionCriteria,
    *,
    component_workers: int = 1,
    entity_resolver: EntityResolver | None = None,
) -> TargetCollectionResult:
    started = time.monotonic()
    project_version = target.project_version

    if not project_version.version_href:
        failure = CollectionFailure(
            target_external_id=(
                project_version.external_id
            ),
            project=project_version.project,
            project_version=project_version.version,
            project_version_href="",
            stage="validate-target",
            error=(
                "Collection target has no "
                "project-version href"
            ),
        )

        return TargetCollectionResult(
            target=target,
            findings=(),
            failures=(failure,),
            elapsed_seconds=(
                time.monotonic() - started
            ),
        )

    entity = ""

    if entity_resolver is not None:
        try:
            entity = str(
                entity_resolver(
                    client,
                    target,
                )
                or ""
            )
        except Exception as error:
            failure = CollectionFailure(
                target_external_id=(
                    project_version.external_id
                ),
                project=project_version.project,
                project_version=(
                    project_version.version
                ),
                project_version_href=(
                    project_version.version_href
                ),
                stage="resolve-entity",
                error=str(error),
            )

            return TargetCollectionResult(
                target=target,
                findings=(),
                failures=(failure,),
                elapsed_seconds=(
                    time.monotonic() - started
                ),
            )

    if (
        criteria.require_entity
        and not entity
    ):
        failure = CollectionFailure(
            target_external_id=(
                project_version.external_id
            ),
            project=project_version.project,
            project_version=project_version.version,
            project_version_href=(
                project_version.version_href
            ),
            stage="resolve-entity",
            error=(
                f"Project does not have a populated "
                f"{criteria.entity_custom_field!r} "
                "custom field"
            ),
        )

        return TargetCollectionResult(
            target=target,
            findings=(),
            failures=(failure,),
            elapsed_seconds=(
                time.monotonic() - started
            ),
        )

    try:
        components = get_vulnerable_components(
            client,
            project_version.version_href,
        )
        components = dedupe_vulnerable_components(
            components
        )
    except Exception as error:
        failure = CollectionFailure(
            target_external_id=(
                project_version.external_id
            ),
            project=project_version.project,
            project_version=project_version.version,
            project_version_href=(
                project_version.version_href
            ),
            stage="load-vulnerable-components",
            error=str(error),
        )

        return TargetCollectionResult(
            target=target,
            findings=(),
            failures=(failure,),
            elapsed_seconds=(
                time.monotonic() - started
            ),
        )

    if not components:
        return TargetCollectionResult(
            target=target,
            findings=(),
            failures=(),
            elapsed_seconds=(
                time.monotonic() - started
            ),
        )

    worker_count = min(
        bounded_worker_count(
            component_workers,
            maximum=MAX_COMPONENT_WORKERS,
        ),
        len(components),
    )
    worker_local = threading.local()

    def worker_client() -> Any:
        if worker_count == 1:
            return client

        local_client = getattr(
            worker_local,
            "blackduck_client",
            None,
        )

        if local_client is None:
            local_client = client.clone_for_worker()
            worker_local.blackduck_client = local_client

        return local_client

    def collect_component(
        item: tuple[int, dict[str, Any]],
    ) -> tuple[
        list[NormalizedFinding],
        CollectionFailure | None,
    ]:
        _, component = item

        try:
            return (
                collect_component_findings(
                    worker_client(),
                    target,
                    component,
                    criteria,
                    entity=entity,
                ),
                None,
            )
        except Exception as error:
            name = str(
                first_value_by_key(
                    component,
                    (
                        "componentName",
                        "name",
                    ),
                )
                or ""
            )
            href = canonical_href(
                get_self_href(component)
            )

            return (
                [],
                CollectionFailure(
                    target_external_id=(
                        project_version.external_id
                    ),
                    project=(
                        project_version.project
                    ),
                    project_version=(
                        project_version.version
                    ),
                    project_version_href=(
                        project_version.version_href
                    ),
                    stage="component-details",
                    error=str(error),
                    component=name,
                    component_href=href,
                ),
            )

    component_results = ordered_parallel_map(
        enumerate(components),
        collect_component,
        workers=worker_count,
        maximum=MAX_COMPONENT_WORKERS,
    )
    findings: list[NormalizedFinding] = []
    failures: list[CollectionFailure] = []
    seen_findings: set[str] = set()

    for component_findings, failure in component_results:
        if failure is not None:
            failures.append(failure)
            continue

        for finding in component_findings:
            if finding.external_id in seen_findings:
                continue

            seen_findings.add(
                finding.external_id
            )
            findings.append(finding)

    return TargetCollectionResult(
        target=target,
        findings=tuple(findings),
        failures=tuple(failures),
        elapsed_seconds=(
            time.monotonic() - started
        ),
    )


def collect_targets(
    client: Any,
    targets: Iterable[CollectionTarget],
    criteria: CollectionCriteria,
    *,
    workers: int = DEFAULT_IO_WORKERS,
    component_workers: int = 1,
    entity_resolver: EntityResolver | None = None,
) -> CollectionRunResult:
    target_list = list(targets)

    if not target_list:
        return CollectionRunResult(
            target_results=(),
        )

    worker_count = min(
        bounded_worker_count(
            workers,
            maximum=MAX_IO_WORKERS,
        ),
        len(target_list),
    )
    worker_local = threading.local()

    def worker_client() -> Any:
        if worker_count == 1:
            return client

        local_client = getattr(
            worker_local,
            "blackduck_client",
            None,
        )

        if local_client is None:
            local_client = client.clone_for_worker()
            worker_local.blackduck_client = local_client

        return local_client

    def collect(
        target: CollectionTarget,
    ) -> TargetCollectionResult:
        return collect_target(
            worker_client(),
            target,
            criteria,
            component_workers=component_workers,
            entity_resolver=entity_resolver,
        )

    results = ordered_parallel_map(
        target_list,
        collect,
        workers=worker_count,
        maximum=MAX_IO_WORKERS,
    )

    return CollectionRunResult(
        target_results=tuple(results),
    )
