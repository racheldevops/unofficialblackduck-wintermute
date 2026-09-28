from __future__ import annotations

import copy
import json
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any

from wintermute.blackduck.criteria import CollectionCriteria
from wintermute.blackduck.models import CollectionTarget, NormalizedFinding
from wintermute.blackduck.occurrences import matched_occurrence_advisory
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
from wintermute.blackduck.circuit_recovery import (
    default_quarantine_path,
    load_active_quarantine,
)
from wintermute.blackduck.request_control import (
    BlackDuckCircuitOpenError,
    blackduck_request_context,
)
from wintermute.concurrency import (
    DEFAULT_IO_WORKERS,
    MAX_COMPONENT_WORKERS,
    MAX_IO_WORKERS,
    bounded_worker_count,
    ordered_parallel_map,
)


EntityResolver = Callable[[Any, CollectionTarget], str]


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


def merge_occurrence_findings(
    first: NormalizedFinding,
    second: NormalizedFinding,
) -> NormalizedFinding:
    left = first.attributes.get("blackduck_occurrences")
    right = second.attributes.get("blackduck_occurrences")
    if not isinstance(left, list) or not isinstance(right, list):
        return first

    occurrences = {}
    for item in left + right:
        if not isinstance(item, dict):
            raise RuntimeError("Normalized occurrence evidence must contain objects")
        key = json.dumps(item, sort_keys=True, separators=(",", ":"))
        occurrences[key] = copy.deepcopy(item)

    attributes = dict(first.attributes)
    attributes["blackduck_occurrences"] = [
        occurrences[key] for key in sorted(occurrences)
    ]
    contexts = {
        context.external_id: context
        for context in first.lineage_contexts + second.lineage_contexts
    }

    return replace(
        first,
        attributes=attributes,
        lineage_contexts=tuple(contexts[key] for key in sorted(contexts)),
    )


def dedupe_normalized_findings(
    findings: Iterable[NormalizedFinding],
) -> tuple[NormalizedFinding, ...]:
    unique: dict[str, NormalizedFinding] = {}
    for finding in findings:
        previous = unique.get(finding.external_id)
        unique[finding.external_id] = (
            finding
            if previous is None
            else merge_occurrence_findings(previous, finding)
        )
    return tuple(unique.values())


@dataclass(frozen=True)
class CollectionRunResult:
    target_results: tuple[TargetCollectionResult, ...]

    @property
    def findings(self) -> tuple[NormalizedFinding, ...]:
        return dedupe_normalized_findings(
            finding
            for result in self.target_results
            for finding in result.findings
        )

    @property
    def failures(self) -> tuple[CollectionFailure, ...]:
        return tuple(
            failure
            for result in self.target_results
            for failure in result.failures
        )

    @property
    def succeeded_target_count(self) -> int:
        return sum(result.status == "ok" for result in self.target_results)

    @property
    def partial_target_count(self) -> int:
        return sum(result.status == "partial" for result in self.target_results)

    @property
    def failed_target_count(self) -> int:
        return sum(result.status == "failed" for result in self.target_results)


def get_vulnerable_components(
    client: Any,
    project_version_href: str,
) -> list[dict[str, Any]]:
    direct_url = (
        f"{canonical_href(project_version_href)}/vulnerable-bom-components"
    )
    try:
        return client.paged_get(direct_url)
    except BlackDuckCircuitOpenError:
        raise
    except RuntimeError as direct_error:
        try:
            version = client.get(project_version_href)
        except BlackDuckCircuitOpenError:
            raise
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


def component_version_href(component: dict[str, Any]) -> str:
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
                if "/api/components/" in href and "/versions/" in href:
                    return canonical_href(href)

    linked = get_link(
        component,
        ("component-version", "componentVersion", "component_version"),
    )
    if linked:
        return canonical_href(linked)

    for href in iter_hrefs(component):
        if "/api/components/" in href and "/versions/" in href:
            return canonical_href(href)
    return ""


def component_details(
    client: Any,
    component: dict[str, Any],
) -> tuple[str, str, str, str]:
    name = str(
        first_value_by_key(component, ("componentName", "name")) or ""
    )
    version = str(
        first_value_by_key(
            component,
            ("componentVersionName", "versionName"),
        ) or ""
    ).strip()
    direct_version = component.get("componentVersion")

    if not version and isinstance(direct_version, (str, int, float)):
        direct_text = str(direct_version).strip()
        if not looks_like_resource_url(direct_text):
            version = direct_text

    if looks_like_resource_url(version):
        version = ""

    version_href = component_version_href(component)
    if version_href and not version:
        try:
            version_resource = client.get(version_href)
        except BlackDuckCircuitOpenError:
            raise
        except RuntimeError:
            version_resource = {}
        else:
            version = str(
                version_resource.get("versionName")
                or version_resource.get("name")
                or first_value_by_key(
                    version_resource,
                    ("componentVersionName", "versionName"),
                )
                or ""
            ).strip()
            if looks_like_resource_url(version):
                version = ""

    return name, version, version_href, canonical_href(get_self_href(component))


def get_policy_rules(
    client: Any,
    component: dict[str, Any],
) -> list[dict[str, Any]]:
    url = get_link(component, ("policy-rules", "policyRules", "policy-rule"))
    if not url:
        return []
    try:
        return client.paged_get(url)
    except BlackDuckCircuitOpenError:
        raise
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
            bool(criteria.policy_name or criteria.policy_rule_id)
            or criteria.include_policy_rule_details
        )
    )
    if not needs_rules:
        return True, "", ""

    rules = get_policy_rules(client, component)
    names = []
    hrefs = []
    for rule in rules:
        name = str(
            first_value_by_key(
                rule,
                ("name", "policyName", "policyRuleName"),
            ) or ""
        )
        href = canonical_href(get_self_href(rule) or get_link(rule, ("self",)))
        if name:
            names.append(name)
        if href:
            hrefs.append(href)
        if criteria.policy_name and name == criteria.policy_name:
            return True, name, href
        if criteria.policy_rule_id and criteria.policy_rule_id in href:
            return True, name, href

    if criteria.policy_name or criteria.policy_rule_id:
        return False, "", ""
    return True, ";".join(sorted_unique(names)), ";".join(sorted_unique(hrefs))


def collect_component_findings(
    client: Any,
    target: CollectionTarget,
    component: dict[str, Any],
    criteria: CollectionCriteria,
    *,
    entity: str = "",
) -> list[NormalizedFinding]:
    name, version, version_href, bom_component_href = component_details(
        client, component
    )
    matched_policy, policy_name, policy_href = policy_match(
        client, component, criteria
    )
    if not matched_policy:
        return []

    score_fields = (
        criteria.score_field,
        "overallScore",
        "baseScore",
        "cvssScore",
    )
    matched = matched_occurrence_advisory(
        client,
        component,
        target.project_version.version_href,
    )
    evidence = None
    if matched is not None:
        advisory, evidence = matched
        vulnerability_items = [advisory]
    else:
        vulnerability_items = []
        vulnerabilities_url = get_link(
            component, ("vulnerabilities", "vulnerability")
        )
        if vulnerabilities_url:
            for item in client.paged_get(vulnerabilities_url):
                extracted = extract_vulnerability_candidates(
                    item,
                    score_fields=score_fields,
                    dedupe_score_fields=(criteria.score_field, "overallScore"),
                )
                vulnerability_items.extend(extracted or [item])
        else:
            vulnerability_items.extend(
                extract_vulnerability_candidates(
                    component,
                    score_fields=score_fields,
                    dedupe_score_fields=(criteria.score_field, "overallScore"),
                )
            )

    findings = []
    for vulnerability in vulnerability_items:
        score = vulnerability_score(vulnerability, score_fields)
        if not criteria.score_passes(score):
            continue

        exploit_available, exploitable = extract_exploit_available(vulnerability)
        if criteria.require_exploit_available and not exploit_available:
            continue

        reachable, reachability, reachability_source = extract_reachability(
            vulnerability
        )
        if criteria.require_reachable and not reachable:
            continue
        if criteria.reachability_mode == "ai" and not reachability_source:
            reachability_source = "ai-reserved"

        attributes = {
            "bom_component_url": bom_component_href,
            "component_version_href": version_href,
            "component_origin_id": str(
                first_value_by_key(
                    component,
                    ("componentOriginId", "originId", "externalId"),
                ) or ""
            ),
            "policy_matched": matched_policy,
        }
        if evidence is not None:
            attributes["blackduck_occurrences"] = [copy.deepcopy(evidence)]
            identifier = evidence["vulnerability"]
        else:
            identifier = vulnerability_identifier(vulnerability)

        findings.append(
            NormalizedFinding(
                project_version=target.project_version,
                component=name,
                component_version=version,
                component_href=version_href or bom_component_href,
                vulnerability=identifier,
                severity=vulnerability_severity(vulnerability, uppercase=True),
                score_field=criteria.score_field,
                score=score,
                vulnerability_href=vulnerability_href(vulnerability),
                cvss_vector=vulnerability_cvss_vector(vulnerability),
                exploit_available=exploit_available,
                exploitable=exploitable,
                reachable=reachable,
                reachability=reachability,
                reachability_source=reachability_source,
                policy_name=policy_name,
                policy_rule_href=policy_href,
                entity=entity,
                lineage_contexts=target.lineage_contexts,
                attributes=attributes,
            )
        )

    return findings


def vulnerable_component_identity(
    component: dict[str, Any],
) -> tuple[str, str, str] | None:
    if isinstance(component.get("vulnerability"), dict):
        return None

    vulnerabilities_url = canonical_href(
        get_link(component, ("vulnerabilities", "vulnerability"))
    )
    if not vulnerabilities_url:
        return None

    name = str(first_value_by_key(component, ("componentName", "name")) or "")
    version = str(
        first_value_by_key(
            component,
            ("componentVersionName", "versionName"),
        ) or ""
    ).strip()
    if not version or looks_like_resource_url(version):
        version = component_version_href(component)
    return name, version, vulnerabilities_url


def dedupe_vulnerable_components(
    components: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique = []
    seen = set()
    for component in components:
        identity = vulnerable_component_identity(component)
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

    def failed(stage: str, error: str) -> TargetCollectionResult:
        return TargetCollectionResult(
            target=target,
            findings=(),
            failures=(
                CollectionFailure(
                    target_external_id=project_version.external_id,
                    project=project_version.project,
                    project_version=project_version.version,
                    project_version_href=project_version.version_href,
                    stage=stage,
                    error=error,
                ),
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    if not project_version.version_href:
        return failed(
            "validate-target",
            "Collection target has no project-version href",
        )

    entity = ""
    if entity_resolver is not None:
        try:
            entity = str(entity_resolver(client, target) or "")
        except BlackDuckCircuitOpenError:
            raise
        except Exception as error:
            return failed("resolve-entity", str(error))

    if criteria.require_entity and not entity:
        return failed(
            "resolve-entity",
            f"Project does not have a populated "
            f"{criteria.entity_custom_field!r} custom field",
        )

    parent_projects = ";".join(sorted({
        context.parent.project
        for context in target.lineage_contexts
        if context.parent.project
    }))

    with blackduck_request_context(
        child_project=project_version.project,
        child_version=project_version.version,
        child_version_href=project_version.version_href,
        parent_projects=parent_projects,
        stage="load-vulnerable-components",
    ):
        try:
            components = dedupe_vulnerable_components(
                get_vulnerable_components(client, project_version.version_href)
            )
        except BlackDuckCircuitOpenError:
            raise
        except Exception as error:
            return failed("load-vulnerable-components", str(error))

    if not components:
        return TargetCollectionResult(
            target=target,
            findings=(),
            failures=(),
            elapsed_seconds=time.monotonic() - started,
        )

    worker_count = min(
        bounded_worker_count(component_workers, maximum=MAX_COMPONENT_WORKERS),
        len(components),
    )
    worker_local = threading.local()

    def worker_client() -> Any:
        if worker_count == 1:
            return client
        local_client = getattr(worker_local, "blackduck_client", None)
        if local_client is None:
            local_client = client.clone_for_worker()
            worker_local.blackduck_client = local_client
        return local_client

    def collect_component(
        item: tuple[int, dict[str, Any]],
    ) -> tuple[list[NormalizedFinding], CollectionFailure | None]:
        _, component = item
        component_name = str(
            first_value_by_key(component, ("componentName", "name")) or ""
        )
        with blackduck_request_context(
            child_project=project_version.project,
            child_version=project_version.version,
            child_version_href=project_version.version_href,
            parent_projects=parent_projects,
            component=component_name,
            stage="component-vulnerabilities",
        ):
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
            except BlackDuckCircuitOpenError:
                raise
            except Exception as error:
                return (
                    [],
                    CollectionFailure(
                        target_external_id=project_version.external_id,
                        project=project_version.project,
                        project_version=project_version.version,
                        project_version_href=project_version.version_href,
                        stage="component-details",
                        error=str(error),
                        component=component_name,
                        component_href=canonical_href(get_self_href(component)),
                    ),
                )

    component_results = ordered_parallel_map(
        enumerate(components),
        collect_component,
        workers=worker_count,
        maximum=MAX_COMPONENT_WORKERS,
    )
    findings = []
    failures = []
    for component_findings, failure in component_results:
        if failure is not None:
            failures.append(failure)
        else:
            findings.extend(component_findings)

    return TargetCollectionResult(
        target=target,
        findings=dedupe_normalized_findings(findings),
        failures=tuple(failures),
        elapsed_seconds=time.monotonic() - started,
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
    quarantined_results = []
    quarantine = load_active_quarantine(default_quarantine_path())

    if quarantine is not None:
        active_targets = []
        for target in target_list:
            project_version = target.project_version
            if project_version.version_href != quarantine.child_version_href:
                active_targets.append(target)
                continue
            quarantined_results.append(
                TargetCollectionResult(
                    target=target,
                    findings=(),
                    failures=(
                        CollectionFailure(
                            target_external_id=project_version.external_id,
                            project=project_version.project,
                            project_version=project_version.version,
                            project_version_href=project_version.version_href,
                            stage="temporary-quarantine",
                            error=(
                                "Black Duck target is temporarily quarantined until "
                                f"{quarantine.retry_after}"
                            ),
                        ),
                    ),
                    elapsed_seconds=0.0,
                )
            )
        target_list = active_targets

    if not target_list:
        return CollectionRunResult(target_results=tuple(quarantined_results))

    worker_count = min(
        bounded_worker_count(workers, maximum=MAX_IO_WORKERS),
        len(target_list),
    )
    worker_local = threading.local()

    def worker_client() -> Any:
        if worker_count == 1:
            return client
        local_client = getattr(worker_local, "blackduck_client", None)
        if local_client is None:
            local_client = client.clone_for_worker()
            worker_local.blackduck_client = local_client
        return local_client

    def collect(target: CollectionTarget) -> TargetCollectionResult:
        with blackduck_request_context(
            child_project=target.project_version.project,
            child_version=target.project_version.version,
            child_version_href=target.project_version.version_href,
            parent_projects=";".join(sorted({
                context.parent.project
                for context in target.lineage_contexts
                if context.parent.project
            })),
            stage="collect-target",
        ):
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
        target_results=tuple(results) + tuple(quarantined_results)
    )
