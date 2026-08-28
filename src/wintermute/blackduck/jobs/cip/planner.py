from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.blackduck.actions.artifacts import (
    write_action_plan,
)
from wintermute.blackduck.actions.cache import (
    JsonCache,
)
from wintermute.blackduck.actions.models import (
    ActionPlan,
    BlackDuckAction,
    stable_digest,
    utc_now,
    utc_text,
)
from wintermute.blackduck.actions.remediation import (
    VulnerabilityRemediationHandler,
)
from wintermute.blackduck.jobs.cip.config import (
    CipConfiguration,
    CipTarget,
)
from wintermute.blackduck.jobs.cip.evaluator import (
    CipAssessment,
    assess_fix,
    build_remediation_action,
)
from wintermute.blackduck.jobs.cip.security_data import (
    CipSecurityData,
)
from wintermute.blackduck.jobs.cip.targeting import (
    CipCandidate,
    TargetReadResult,
    load_target_candidates,
)
from wintermute.concurrency import (
    ordered_parallel_map,
)
from wintermute.scm.providers.gitlab.client import (
    GitLabRepositoryRef,
)
from wintermute.scm.providers.gitlab.commits import (
    GitLabCommitClient,
)


EVALUATOR_VERSION = "3"


@dataclass(frozen=True)
class CipPlanningResult:
    plan: ActionPlan
    path: Path
    candidate_count: int
    assessment_count: int
    action_count: int
    failure_count: int
    scanned_occurrence_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan.plan_id,
            "plan_digest": self.plan.digest,
            "path": str(self.path),
            "candidate_count": (
                self.candidate_count
            ),
            "assessment_count": (
                self.assessment_count
            ),
            "action_count": self.action_count,
            "failure_count": (
                self.failure_count
            ),
            "scanned_occurrence_count": (
                self.scanned_occurrence_count
            ),
        }


def target_cursor_key(
    target: CipTarget,
) -> str:
    return stable_digest(
        target.as_dict()
    )


def cursor_offset(
    cache: JsonCache,
    target: CipTarget,
    *,
    refresh: bool,
) -> int:
    if refresh:
        return 0

    value = cache.get(
        target_cursor_key(target)
    )

    if not isinstance(value, dict):
        return 0

    try:
        offset = int(
            value.get("next_offset") or 0
        )
    except (
        TypeError,
        ValueError,
    ):
        return 0

    return max(0, offset)


def candidate_budgets(
    targets: tuple[CipTarget, ...],
    maximum: int,
    scheduler_index: int,
) -> list[tuple[CipTarget, int]]:
    if not targets or maximum < 1:
        return []

    rotated = [
        targets[
            (scheduler_index + index)
            % len(targets)
        ]
        for index in range(len(targets))
    ]
    base, remainder = divmod(
        maximum,
        len(rotated),
    )
    result: list[
        tuple[CipTarget, int]
    ] = []

    for index, target in enumerate(rotated):
        budget = (
            base
            + (1 if index < remainder else 0)
        )

        if budget > 0:
            result.append(
                (target, budget)
            )

    return result


def unavailable_assessment(
    candidate: CipCandidate,
    repository: GitLabRepositoryRef,
    *,
    status: str,
    detail: str,
    evidence: dict[str, Any],
) -> CipAssessment:
    return CipAssessment(
        cve=candidate.cve,
        branch=candidate.target.cip_branch,
        tag=candidate.target.cip_tag,
        tag_commit=repository.commit,
        status=status,
        fix_commits=(),
        included_commits=(),
        missing_commits=(),
        evidence=evidence,
        detail=detail,
    )


def create_cip_plan(
    client: Any,
    configuration: CipConfiguration,
    gitlab: GitLabCommitClient,
    *,
    plan_root: str | Path,
    assessment_cache_path: str | Path,
    target_cursor_cache_path: str | Path,
    alias_cache_path: str | Path,
    target_page_size: int = 25,
    max_occurrences_per_target: int = 25,
    max_candidates_per_run: int = 10,
    progress_every: int = 10,
    refresh_target_cursors: bool = False,
) -> CipPlanningResult:
    configuration.validate()

    for name, value in (
        ("target_page_size", target_page_size),
        (
            "max_occurrences_per_target",
            max_occurrences_per_target,
        ),
        (
            "max_candidates_per_run",
            max_candidates_per_run,
        ),
        ("progress_every", progress_every),
    ):
        if value < 1:
            raise ValueError(
                f"{name} must be positive"
            )

    maximum_candidates = min(
        max_candidates_per_run,
        configuration.limits.maximum_actions,
    )
    security_ref = (
        gitlab.resolve_repository_ref(
            configuration
            .security_repository
            .location,
            configuration
            .security_repository
            .revision,
        )
    )
    security_data = CipSecurityData(
        gitlab,
        security_ref,
    )
    kernel_repositories = {
        tag: gitlab.resolve_repository_ref(
            configuration
            .kernel_repository
            .location,
            tag,
            tag=True,
        )
        for tag in sorted(
            {
                target.cip_tag
                for target
                in configuration.targets
            }
        )
    }
    cursor_cache = JsonCache(
        target_cursor_cache_path,
        namespace="cip-target-cursors",
        identity={
            "blackduck_base_url": (
                configuration.blackduck_base_url
            ),
            "schema_version": 1,
        },
    )
    alias_cache = JsonCache(
        alias_cache_path,
        namespace="cip-vulnerability-aliases",
        identity={
            "blackduck_base_url": (
                configuration.blackduck_base_url
            ),
            "schema_version": 1,
        },
    )
    cursor_cache.load()
    alias_cache.load()
    scheduler = cursor_cache.get(
        "target-scheduler"
    )
    scheduler_index = 0

    if (
        not refresh_target_cursors
        and isinstance(scheduler, dict)
    ):
        try:
            scheduler_index = int(
                scheduler.get("next_index")
                or 0
            )
        except (
            TypeError,
            ValueError,
        ):
            scheduler_index = 0

    scheduled = candidate_budgets(
        configuration.targets,
        maximum_candidates,
        scheduler_index,
    )
    local = threading.local()

    def load_target(
        item: tuple[CipTarget, int],
    ) -> TargetReadResult:
        target, budget = item
        worker = getattr(
            local,
            "client",
            None,
        )

        if worker is None:
            worker = (
                client.clone_for_uncached_reads()
            )
            local.client = worker

        start_offset = cursor_offset(
            cursor_cache,
            target,
            refresh=refresh_target_cursors,
        )

        return load_target_candidates(
            worker,
            target,
            start_offset=start_offset,
            page_size=target_page_size,
            max_occurrences=(
                max_occurrences_per_target
            ),
            max_candidates=budget,
            alias_cache=alias_cache,
            progress_every=progress_every,
        )

    if scheduled:
        target_results = (
            ordered_parallel_map(
                scheduled,
                load_target,
                workers=min(
                    configuration.read_workers,
                    len(scheduled),
                ),
                maximum=8,
            )
        )
    else:
        target_results = []

    for result in target_results:
        cursor_cache.set(
            target_cursor_key(result.target),
            result.cursor_payload(),
        )

    if configuration.targets:
        cursor_cache.set(
            "target-scheduler",
            {
                "next_index": (
                    scheduler_index
                    + len(scheduled)
                )
                % len(configuration.targets)
            },
        )

    cursor_cache.prune(max_entries=10000)
    cursor_cache.save()
    alias_cache.prune(max_entries=50000)
    alias_cache.save()
    candidates = tuple(
        candidate
        for result in target_results
        for candidate in result.candidates
    )
    failures = [
        failure.as_dict()
        for result in target_results
        for failure in result.failures
    ]
    scanned_occurrence_count = sum(
        result.scanned_count
        for result in target_results
    )
    cursor_rows = [
        {
            "target": (
                result.target.as_dict()
            ),
            "start_offset": (
                result.start_offset
            ),
            "next_offset": (
                result.next_offset
            ),
            "total_count": (
                result.total_count
            ),
            "scanned_count": (
                result.scanned_count
            ),
            "matching_occurrence_count": (
                result.occurrence_count
            ),
            "candidate_count": len(
                result.candidates
            ),
            "unresolved_count": (
                result.unresolved_count
            ),
            "wrapped": result.wrapped,
        }
        for result in target_results
    ]
    unique_tasks: dict[
        tuple[str, str, str],
        CipCandidate,
    ] = {}

    for candidate in candidates:
        key = (
            candidate.target.cip_tag,
            candidate.target.cip_branch,
            candidate.cve,
        )
        unique_tasks.setdefault(
            key,
            candidate,
        )

    assessment_cache = JsonCache(
        assessment_cache_path,
        namespace="cip-assessments",
        identity={
            "evaluator_version": (
                EVALUATOR_VERSION
            ),
            "kernel_repository": (
                configuration
                .kernel_repository
                .location
            ),
            "security_repository": (
                configuration
                .security_repository
                .location
            ),
        },
    )
    assessment_cache.load()

    def evaluate(
        item: tuple[
            tuple[str, str, str],
            CipCandidate,
        ],
    ) -> tuple[
        tuple[str, str, str],
        CipAssessment,
    ]:
        key, candidate = item
        tag, branch, cve = key
        kernel_repository = (
            kernel_repositories[tag]
        )
        cache_key = "|".join(
            [
                EVALUATOR_VERSION,
                cve,
                branch,
                kernel_repository.commit,
                security_ref.commit,
            ]
        )
        cached = assessment_cache.get(
            cache_key
        )

        if isinstance(cached, dict):
            return (
                key,
                CipAssessment.from_dict(
                    cached
                ),
            )

        try:
            lookup = security_data.lookup(
                cve,
                branch,
            )

            if lookup.record is None:
                assessment = (
                    unavailable_assessment(
                        candidate,
                        kernel_repository,
                        status=lookup.status,
                        detail=lookup.detail,
                        evidence={
                            "provider": (
                                "cip-kernel-sec"
                            ),
                            "security_repository": (
                                security_ref
                                .repository_url
                            ),
                            "security_revision": (
                                security_ref.commit
                            ),
                            "source_path": (
                                lookup.source_path
                            ),
                            "requested_branch": (
                                branch
                            ),
                        },
                    )
                )
            else:
                assessment = assess_fix(
                    gitlab,
                    kernel_repository,
                    tag=tag,
                    record=lookup.record,
                )
        except Exception as error:
            assessment = unavailable_assessment(
                candidate,
                kernel_repository,
                status="error",
                detail=str(error),
                evidence={
                    "provider": "cip-kernel-sec",
                    "security_repository": (
                        security_ref.repository_url
                    ),
                    "security_revision": (
                        security_ref.commit
                    ),
                    "requested_branch": branch,
                },
            )

        if assessment.status != "error":
            assessment_cache.set(
                cache_key,
                assessment.as_dict(),
            )

        return key, assessment

    if unique_tasks:
        assessment_items = (
            ordered_parallel_map(
                sorted(
                    unique_tasks.items()
                ),
                evaluate,
                workers=min(
                    configuration
                    .evidence_workers,
                    len(unique_tasks),
                ),
                maximum=8,
            )
        )
    else:
        assessment_items = []

    assessments = dict(assessment_items)
    assessment_cache.prune(
        max_entries=10000
    )
    assessment_cache.save()
    remediable_candidates = [
        candidate
        for candidate in candidates
        if assessments[
            (
                candidate.target.cip_tag,
                candidate.target.cip_branch,
                candidate.cve,
            )
        ].remediable
    ]
    state_local = threading.local()

    def read_state(
        candidate: CipCandidate,
    ) -> tuple[
        CipCandidate,
        dict[str, Any] | None,
        str,
    ]:
        worker = getattr(
            state_local,
            "client",
            None,
        )

        if worker is None:
            worker = (
                client.clone_for_uncached_reads()
            )
            state_local.client = worker

        handler = getattr(
            state_local,
            "handler",
            None,
        )

        if handler is None:
            handler = (
                VulnerabilityRemediationHandler(
                    worker,
                    preserve_existing_decisions=(
                        configuration
                        .preserve_existing_decisions
                    ),
                    allowed_statuses=(
                        configuration
                        .desired_status,
                    ),
                )
            )
            state_local.handler = handler

        try:
            state = handler.read_target_state(
                candidate.remediation_target,
                ownership_marker=(
                    "wintermute:cip:v1"
                ),
            )
            return candidate, state, ""
        except Exception as error:
            return candidate, None, str(error)

    if remediable_candidates:
        state_results = (
            ordered_parallel_map(
                remediable_candidates,
                read_state,
                workers=min(
                    configuration.read_workers,
                    len(
                        remediable_candidates
                    ),
                ),
                maximum=8,
            )
        )
    else:
        state_results = []

    states: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    for candidate, state, error in (
        state_results
    ):
        identity = (
            candidate.cve,
            candidate
            .remediation_target
            .resource_href,
        )

        if error:
            failures.append(
                {
                    "project_version_href": (
                        candidate.target
                        .project_version_href
                    ),
                    "component_version_href": (
                        candidate.target
                        .component_version_href
                    ),
                    "cip_tag": (
                        candidate.target.cip_tag
                    ),
                    "cve": candidate.cve,
                    "stage": (
                        "read-remediation-state"
                    ),
                    "error": error,
                }
            )
            continue

        if state is not None:
            states[identity] = state

    assessed_at = utc_text(utc_now())
    actions: dict[
        str,
        BlackDuckAction,
    ] = {}
    assessment_rows: list[
        dict[str, Any]
    ] = []

    for candidate in candidates:
        key = (
            candidate.target.cip_tag,
            candidate.target.cip_branch,
            candidate.cve,
        )
        assessment = assessments[key]
        identity = (
            candidate.cve,
            candidate
            .remediation_target
            .resource_href,
        )
        state = states.get(identity)
        assessment_rows.append(
            {
                "target": candidate.as_dict(),
                "assessment": (
                    assessment.as_dict()
                ),
                "observed_state": (
                    state or {}
                ),
            }
        )

        if assessment.status == "error":
            failures.append(
                {
                    "project_version_href": (
                        candidate.target
                        .project_version_href
                    ),
                    "component_version_href": (
                        candidate.target
                        .component_version_href
                    ),
                    "cip_tag": (
                        candidate.target.cip_tag
                    ),
                    "cve": candidate.cve,
                    "stage": (
                        "evaluate-cip-evidence"
                    ),
                    "error": assessment.detail,
                }
            )

        if state is None:
            continue

        action = build_remediation_action(
            assessment,
            blackduck_target=(
                candidate.remediation_target
            ),
            observed_state=state,
            desired_status=(
                configuration.desired_status
            ),
            assessed_at=assessed_at,
            preserve_existing_decisions=(
                configuration
                .preserve_existing_decisions
            ),
        )

        if action is not None:
            actions.setdefault(
                action.action_id,
                action,
            )

    ordered_actions = tuple(
        actions[key]
        for key in sorted(actions)
    )
    plan = ActionPlan.create(
        producer="cip-remediation",
        producer_version=EVALUATOR_VERSION,
        blackduck_base_url=(
            configuration.blackduck_base_url
        ),
        actions=ordered_actions,
        limits=configuration.limits,
        metadata={
            "configuration_digest": (
                configuration.digest
            ),
            "kernel_repository": {
                "location": (
                    configuration
                    .kernel_repository
                    .location
                ),
                "tags": {
                    tag: repository.commit
                    for tag, repository
                    in sorted(
                        kernel_repositories.items()
                    )
                },
            },
            "security_repository": {
                "location": (
                    security_ref.repository_url
                ),
                "revision": (
                    security_ref.commit
                ),
            },
            "candidate_count": len(candidates),
            "assessment_count": len(
                assessment_rows
            ),
            "action_count": len(
                ordered_actions
            ),
            "failure_count": len(failures),
            "scanned_occurrence_count": (
                scanned_occurrence_count
            ),
        },
        expires_in_hours=(
            configuration.plan_lifetime_hours
        ),
    )
    path = write_action_plan(
        plan_root,
        plan,
        attachments={
            "assessments.json": {
                "schema_version": 1,
                "assessments": (
                    assessment_rows
                ),
            },
            "cursors.json": {
                "schema_version": 1,
                "targets": cursor_rows,
            },
            "failures.json": {
                "schema_version": 1,
                "failures": failures,
            },
        },
    )

    return CipPlanningResult(
        plan=plan,
        path=path,
        candidate_count=len(candidates),
        assessment_count=len(
            assessment_rows
        ),
        action_count=len(ordered_actions),
        failure_count=len(failures),
        scanned_occurrence_count=(
            scanned_occurrence_count
        ),
    )
