from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from wintermute.concurrency import (
    bounded_worker_count,
    ordered_parallel_map,
)
from wintermute.paths import output_root
from wintermute.scm.controls import (
    ControlFailure,
    ControlInventory,
    ControlKind,
    ControlObservation,
    ControlState,
)
from wintermute.scm.evidence import (
    EvidenceFailure,
    EvidenceInventory,
    EvidenceKind,
    EvidenceObservation,
    EvidenceScope,
    canonical_value,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.observations import (
    ScmObservationResult,
)
from wintermute.scm.providers.gitlab.cache import (
    GitLabCapabilityCache,
)
from wintermute.scm.providers.gitlab.client import (
    GitLabRepositoryRef,
    GitLabRestError,
)
from wintermute.scm.providers.gitlab.inventory import (
    GitLabClient,
)


DEFAULT_BLACKDUCK_MARKERS = (
    "blackduck",
    "black-duck",
    "synopsys-detect",
    "detect.sh",
    "detect10.sh",
)
DEFAULT_MAX_CI_FILES = 25
DEFAULT_MAX_CI_BYTES = 2 * 1024 * 1024

_LOCAL_INCLUDE_RE = re.compile(
    r"""^\s*(?:-\s*)?local:\s*['"]?([^'"#]+)['"]?"""
    r"""\s*(?:#.*)?$"""
)
_SCALAR_INCLUDE_RE = re.compile(
    r"""^\s*include:\s*['"]([^'"]+)['"]\s*"""
    r"""(?:#.*)?$"""
)
_LIST_INCLUDE_RE = re.compile(
    r"""^\s*-\s*['"]([^'"]+)['"]\s*(?:#.*)?$"""
)


@dataclass(frozen=True)
class GitLabResourceFailure:
    stage: str
    error: str


@dataclass(frozen=True)
class GitLabProjectResources:
    repository: Repository
    ci_present: bool
    ci_digest: str
    ci_size: int
    ci_paths: tuple[str, ...]
    ci_complete: bool
    blackduck_configured: bool
    languages: dict[str, Any]
    pipelines: tuple[dict[str, Any], ...]
    default_branch_protected: bool | None
    failures: tuple[
        GitLabResourceFailure,
        ...
    ] = ()


def active_repositories(
    inventory: RepositoryInventory,
) -> tuple[Repository, ...]:
    return tuple(
        sorted(
            inventory.repositories,
            key=lambda value: (
                value.name_with_owner.casefold(),
                value.repository_id,
            ),
        )
    )


def project_reference(
    repository: Repository,
) -> GitLabRepositoryRef:
    return GitLabRepositoryRef(
        repository_url=repository.canonical_url,
        project_path=repository.name_with_owner,
        revision=(
            repository.default_branch
            or repository.head_sha
        ),
        commit=(
            repository.head_sha
            or repository.default_branch
        ),
    )


def normalize_ci_path(value: str) -> str:
    selected = str(value or "").strip()

    if selected.startswith("/"):
        selected = selected[1:]

    path = Path(selected)

    if (
        not selected
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in selected
    ):
        raise ValueError(
            f"Invalid GitLab CI path: {value!r}"
        )

    return path.as_posix()


def indentation(value: str) -> int:
    return len(value) - len(
        value.lstrip(" ")
    )


def local_include_path(
    value: str,
) -> str:
    selected = str(value or "").strip()

    if (
        not selected
        or selected.startswith(
            ("http://", "https://")
        )
        or "@" in selected
    ):
        return ""

    return normalize_ci_path(selected)


def local_includes(
    value: str,
) -> tuple[str, ...]:
    includes: set[str] = set()
    include_indent: int | None = None
    direct_item_indent: int | None = None

    for line in value.splitlines():
        stripped = line.strip()

        if (
            not stripped
            or stripped.startswith("#")
        ):
            continue

        current_indent = indentation(line)
        scalar_match = _SCALAR_INCLUDE_RE.match(
            line
        )

        if scalar_match:
            selected = local_include_path(
                scalar_match.group(1)
            )

            if selected:
                includes.add(selected)

            include_indent = None
            direct_item_indent = None
            continue

        if stripped == "include:":
            include_indent = current_indent
            direct_item_indent = None
            continue

        if include_indent is None:
            continue

        if current_indent <= include_indent:
            include_indent = None
            direct_item_indent = None
            continue

        if direct_item_indent is None:
            direct_item_indent = current_indent

        local_match = _LOCAL_INCLUDE_RE.match(
            line
        )

        if local_match:
            selected = local_include_path(
                local_match.group(1)
            )

            if selected:
                includes.add(selected)

            continue

        if current_indent != direct_item_indent:
            continue

        list_match = _LIST_INCLUDE_RE.match(
            line
        )

        if list_match:
            selected = local_include_path(
                list_match.group(1)
            )

            if selected:
                includes.add(selected)

    return tuple(sorted(includes))


def read_ci_files(
    client: GitLabClient,
    repository: Repository,
    *,
    max_files: int = DEFAULT_MAX_CI_FILES,
    max_bytes: int = DEFAULT_MAX_CI_BYTES,
) -> tuple[
    dict[str, bytes],
    tuple[GitLabResourceFailure, ...],
    bool,
]:
    if max_files < 1:
        raise ValueError(
            "max_files must be positive"
        )

    if max_bytes < 1:
        raise ValueError(
            "max_bytes must be positive"
        )

    if not repository.default_branch:
        return {}, (), True

    ci_config_path = getattr(
        client,
        "ci_config_path",
        None,
    )
    root_path = (
        str(
            ci_config_path(
                repository.repository_id
            )
        )
        if callable(ci_config_path)
        else ".gitlab-ci.yml"
    )

    if "@" in root_path:
        return (
            {},
            (
                GitLabResourceFailure(
                    stage="read-gitlab-ci",
                    error=(
                        "External-project CI configuration "
                        "is not supported"
                    ),
                ),
            ),
            False,
        )

    try:
        root_path = normalize_ci_path(
            root_path
        )
    except ValueError as error:
        return (
            {},
            (
                GitLabResourceFailure(
                    stage="read-gitlab-ci",
                    error=str(error),
                ),
            ),
            False,
        )

    reference = project_reference(
        repository
    )
    pending = [root_path]
    visited: set[str] = set()
    files: dict[str, bytes] = {}
    failures: list[
        GitLabResourceFailure
    ] = []
    total_bytes = 0
    complete = True

    while pending:
        if len(files) >= max_files:
            complete = False
            failures.append(
                GitLabResourceFailure(
                    stage="read-gitlab-ci-include",
                    error=(
                        f"CI include file limit "
                        f"{max_files} was reached"
                    ),
                )
            )
            break

        path = pending.pop(0)

        if path in visited:
            continue

        visited.add(path)

        try:
            content = (
                client.try_read_repository_file(
                    reference,
                    path,
                )
            )
        except Exception as error:
            complete = False
            failures.append(
                GitLabResourceFailure(
                    stage="read-gitlab-ci",
                    error=f"{path}: {error}",
                )
            )
            continue

        if content is None:
            if path != root_path:
                complete = False
                failures.append(
                    GitLabResourceFailure(
                        stage=(
                            "read-gitlab-ci-include"
                        ),
                        error=(
                            "Local CI include was not "
                            f"found: {path}"
                        ),
                    )
                )

            continue

        total_bytes += len(content)

        if total_bytes > max_bytes:
            complete = False
            failures.append(
                GitLabResourceFailure(
                    stage="read-gitlab-ci-include",
                    error=(
                        "CI configuration exceeded the "
                        f"{max_bytes}-byte read budget"
                    ),
                )
            )
            break

        files[path] = content
        text = content.decode(
            "utf-8",
            errors="replace",
        )

        for included in local_includes(text):
            if (
                included not in visited
                and included not in pending
            ):
                pending.append(included)

    return (
        files,
        tuple(failures),
        complete,
    )


def read_project_resources(
    client: GitLabClient,
    repository: Repository,
    *,
    markers: tuple[str, ...],
    pipeline_limit: int,
    capability_cache: GitLabCapabilityCache,
) -> GitLabProjectResources:
    failures: list[
        GitLabResourceFailure
    ] = []
    (
        ci_files,
        ci_failures,
        ci_complete,
    ) = read_ci_files(
        client,
        repository,
    )
    failures.extend(ci_failures)
    ci_present = bool(ci_files)
    ci_size = sum(
        len(content)
        for content in ci_files.values()
    )
    digest = sha256()

    for path, content in sorted(
        ci_files.items()
    ):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")

    ci_digest = (
        digest.hexdigest()
        if ci_files
        else ""
    )
    combined = "\n".join(
        content.decode(
            "utf-8",
            errors="replace",
        )
        for content in ci_files.values()
    ).casefold()
    blackduck_configured = any(
        marker.casefold() in combined
        for marker in markers
    )
    languages: dict[str, Any] = {}

    try:
        languages = (
            client.project_languages(
                repository.repository_id
            )
        )
    except Exception as error:
        failures.append(
            GitLabResourceFailure(
                stage="read-languages",
                error=str(error),
            )
        )

    pipelines: tuple[
        dict[str, Any],
        ...
    ] = ()

    if ci_present and pipeline_limit > 0:
        cached_denial = capability_cache.denied(
            repository.repository_id,
            "pipelines",
        )

        if cached_denial:
            failures.append(
                GitLabResourceFailure(
                    stage="read-pipelines",
                    error=(
                        "Cached GitLab pipeline access "
                        f"denial: {cached_denial}"
                    ),
                )
            )
        else:
            try:
                pipelines = (
                    client.recent_pipelines(
                        repository.repository_id,
                        limit=pipeline_limit,
                    )
                )
                capability_cache.clear(
                    repository.repository_id,
                    "pipelines",
                )
            except GitLabRestError as error:
                if error.status_code == 403:
                    capability_cache.record_denied(
                        repository.repository_id,
                        "pipelines",
                        str(error),
                    )

                failures.append(
                    GitLabResourceFailure(
                        stage="read-pipelines",
                        error=str(error),
                    )
                )
            except Exception as error:
                failures.append(
                    GitLabResourceFailure(
                        stage="read-pipelines",
                        error=str(error),
                    )
                )

    protected: bool | None = None

    if repository.default_branch:
        try:
            protected = (
                client.protected_branch(
                    repository.repository_id,
                    repository.default_branch,
                )
                is not None
            )
        except Exception as error:
            failures.append(
                GitLabResourceFailure(
                    stage="read-protected-branch",
                    error=str(error),
                )
            )

    return GitLabProjectResources(
        repository=repository,
        ci_present=ci_present,
        ci_digest=ci_digest,
        ci_size=ci_size,
        ci_paths=tuple(sorted(ci_files)),
        ci_complete=ci_complete,
        blackduck_configured=(
            blackduck_configured
        ),
        languages=languages,
        pipelines=pipelines,
        default_branch_protected=protected,
        failures=tuple(failures),
    )


def resource_failure(
    resources: GitLabProjectResources,
    stage: str,
) -> GitLabResourceFailure | None:
    return next(
        (
            failure
            for failure in resources.failures
            if failure.stage == stage
        ),
        None,
    )


def pipeline_value(
    pipeline: dict[str, Any],
    *names: str,
) -> str:
    for name in names:
        value = pipeline.get(name)

        if value not in (None, ""):
            return str(value)

    return ""


def evidence_for_resources(
    tenant: ScmTenant,
    resources: GitLabProjectResources,
) -> EvidenceInventory:
    repository = resources.repository
    observations: list[
        EvidenceObservation
    ] = []
    language_values: dict[str, float] = {}

    for name, raw_value in (
        resources.languages.items()
    ):
        try:
            percentage = float(raw_value)
        except (
            TypeError,
            ValueError,
        ):
            continue

        if percentage > 0:
            language_values[
                str(name).casefold()
            ] = percentage

    observations.append(
        EvidenceObservation(
            provider="gitlab",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            kind=(
                EvidenceKind
                .REPOSITORY_LANGUAGE_INVENTORY
            ),
            scope=EvidenceScope.REPOSITORY,
            key="languages",
            source="gitlab-languages",
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            attributes=(
                (
                    "complete",
                    canonical_value(
                        bool(resources.languages)
                    ),
                ),
                (
                    "measurement",
                    "percentage",
                ),
                (
                    "percentages",
                    canonical_value(
                        language_values
                    ),
                ),
            ),
        )
    )
    observations.extend(
        EvidenceObservation(
            provider="gitlab",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            kind=(
                EvidenceKind.REPOSITORY_LANGUAGE
            ),
            scope=EvidenceScope.REPOSITORY,
            key=name,
            source="gitlab-languages",
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            attributes=(
                (
                    "percentage",
                    str(percentage),
                ),
            ),
        )
        for name, percentage
        in sorted(language_values.items())
    )
    ci_failure = resource_failure(
        resources,
        "read-gitlab-ci",
    )
    ci_status = (
        "failed"
        if ci_failure is not None
        else (
            "available"
            if resources.ci_present
            else "missing"
        )
    )
    observations.append(
        EvidenceObservation(
            provider="gitlab",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            kind=(
                EvidenceKind
                .REPOSITORY_WORKFLOW_INVENTORY
            ),
            scope=EvidenceScope.REPOSITORY,
            key="gitlab-ci",
            source="gitlab-ci",
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            attributes=(
                ("status", ci_status),
                (
                    "workflow_count",
                    str(len(resources.ci_paths)),
                ),
                (
                    "complete",
                    canonical_value(
                        resources.ci_complete
                    ),
                ),
                (
                    "blackduck_configured",
                    canonical_value(
                        resources
                        .blackduck_configured
                    ),
                ),
                (
                    "paths",
                    canonical_value(
                        list(resources.ci_paths)
                    ),
                ),
            ),
        )
    )

    if resources.ci_present:
        observations.append(
            EvidenceObservation(
                provider="gitlab",
                provider_instance=(
                    tenant.provider_instance
                ),
                tenant_id=tenant.tenant_id,
                kind=(
                    EvidenceKind
                    .REPOSITORY_WORKFLOW
                ),
                scope=(
                    EvidenceScope.REPOSITORY
                ),
                key="gitlab-ci-configuration",
                source="gitlab-ci",
                repository_external_id=(
                    repository.external_id
                ),
                name_with_owner=(
                    repository.name_with_owner
                ),
                attributes=(
                    (
                        "sha256",
                        resources.ci_digest,
                    ),
                    (
                        "size",
                        str(resources.ci_size),
                    ),
                    (
                        "paths",
                        canonical_value(
                            list(resources.ci_paths)
                        ),
                    ),
                    (
                        "blackduck_configured",
                        canonical_value(
                            resources
                            .blackduck_configured
                        ),
                    ),
                ),
            )
        )

    observations.extend(
        EvidenceObservation(
            provider="gitlab",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            kind=(
                EvidenceKind.REPOSITORY_WORKFLOW
            ),
            scope=EvidenceScope.REPOSITORY,
            key=(
                "pipeline:"
                + pipeline_value(
                    pipeline,
                    "id",
                )
            ),
            source="gitlab-pipeline",
            provider_resource_id=(
                pipeline_value(
                    pipeline,
                    "id",
                )
            ),
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            attributes=(
                (
                    "status",
                    pipeline_value(
                        pipeline,
                        "status",
                    ),
                ),
                (
                    "ref",
                    pipeline_value(
                        pipeline,
                        "ref",
                    ),
                ),
                (
                    "sha",
                    pipeline_value(
                        pipeline,
                        "sha",
                    ),
                ),
                (
                    "created_at",
                    pipeline_value(
                        pipeline,
                        "created_at",
                        "createdAt",
                    ),
                ),
                (
                    "updated_at",
                    pipeline_value(
                        pipeline,
                        "updated_at",
                        "updatedAt",
                    ),
                ),
                (
                    "web_url",
                    pipeline_value(
                        pipeline,
                        "web_url",
                        "webUrl",
                        "webPath",
                    ),
                ),
            ),
        )
        for pipeline in resources.pipelines
        if pipeline_value(
            pipeline,
            "id",
        )
    )
    failures = tuple(
        EvidenceFailure(
            provider="gitlab",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            stage=failure.stage,
            error=failure.error,
        )
        for failure in resources.failures
    )

    return EvidenceInventory(
        observations=tuple(observations),
        failures=failures,
    )


def controls_for_resources(
    tenant: ScmTenant,
    resources: GitLabProjectResources,
) -> ControlInventory:
    repository = resources.repository
    ci_failure = resource_failure(
        resources,
        "read-gitlab-ci",
    )
    protected_failure = resource_failure(
        resources,
        "read-protected-branch",
    )

    if ci_failure is not None:
        policy_state = ControlState.FAILED
        workflow_state = ControlState.FAILED
        policy_message = ci_failure.error
        workflow_message = ci_failure.error
    elif resources.blackduck_configured:
        policy_state = ControlState.COMPLIANT
        workflow_state = (
            ControlState.COMPLIANT
        )
        policy_message = (
            "GitLab CI includes a Black Duck "
            "scan marker"
        )
        workflow_message = (
            "GitLab CI includes a Black Duck "
            "scan workflow"
        )
    elif (
        resources.ci_present
        and not resources.ci_complete
    ):
        policy_state = ControlState.UNKNOWN
        workflow_state = ControlState.UNKNOWN
        policy_message = (
            "GitLab CI evidence is incomplete"
        )
        workflow_message = policy_message
    elif resources.ci_present:
        policy_state = (
            ControlState.NONCOMPLIANT
        )
        workflow_state = (
            ControlState.NONCOMPLIANT
        )
        policy_message = (
            "GitLab CI does not include a "
            "Black Duck scan marker"
        )
        workflow_message = policy_message
    else:
        policy_state = (
            ControlState.NONCOMPLIANT
        )
        workflow_state = (
            ControlState.NONCOMPLIANT
        )
        policy_message = (
            "GitLab CI configuration is missing"
        )
        workflow_message = policy_message

    if protected_failure is not None:
        branch_state = ControlState.FAILED
        branch_message = (
            protected_failure.error
        )
    elif not repository.default_branch:
        branch_state = ControlState.UNKNOWN
        branch_message = (
            "Repository has no default branch"
        )
    elif resources.default_branch_protected:
        branch_state = ControlState.COMPLIANT
        branch_message = (
            "GitLab default branch is protected"
        )
    else:
        branch_state = (
            ControlState.NONCOMPLIANT
        )
        branch_message = (
            "GitLab default branch is not protected"
        )

    observations = (
        ControlObservation(
            provider="gitlab",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            control=(
                ControlKind.ONBOARDING_POLICY
            ),
            state=policy_state,
            source="gitlab-ci",
            expected=(
                "Black Duck scan marker"
            ),
            observed=(
                "configured"
                if resources.blackduck_configured
                else "not-configured"
            ),
            message=policy_message,
        ),
        ControlObservation(
            provider="gitlab",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            control=(
                ControlKind
                .REQUIRED_SCAN_WORKFLOW
            ),
            state=workflow_state,
            source="gitlab-ci",
            expected=(
                "Black Duck scan workflow"
            ),
            observed=(
                ";".join(resources.ci_paths)
                if resources.ci_paths
                else "<missing>"
            ),
            message=workflow_message,
        ),
        ControlObservation(
            provider="gitlab",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            control=(
                ControlKind
                .PROTECTED_DEFAULT_BRANCH
            ),
            state=branch_state,
            source="gitlab-protected-branch",
            expected="protected default branch",
            observed=(
                repository.default_branch
                or "<missing>"
            ),
            message=branch_message,
        ),
    )
    failures = tuple(
        ControlFailure(
            provider="gitlab",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            stage=failure.stage,
            error=failure.error,
        )
        for failure in resources.failures
        if failure.stage in {
            "read-gitlab-ci",
            "read-protected-branch",
        }
    )

    return ControlInventory(
        observations=observations,
        failures=failures,
    )


class GitLabObservationProvider:
    provider = "gitlab"

    def __init__(
        self,
        client: GitLabClient,
        *,
        workers: int = 4,
        pipeline_limit: int = 3,
        blackduck_markers: tuple[
            str,
            ...
        ] = DEFAULT_BLACKDUCK_MARKERS,
        capability_cache_path: (
            str | Path | None
        ) = None,
    ) -> None:
        if not 1 <= workers <= 8:
            raise ValueError(
                "workers must be between 1 and 8"
            )

        if not 0 <= pipeline_limit <= 100:
            raise ValueError(
                "pipeline_limit must be between "
                "0 and 100"
            )

        self.client = client
        self.provider_instance = (
            client.provider_instance
        )
        self.workers = workers
        self.pipeline_limit = pipeline_limit
        self.blackduck_markers = tuple(
            str(value).casefold()
            for value in blackduck_markers
            if str(value).strip()
        )
        selected_cache_path = (
            Path(capability_cache_path)
            if capability_cache_path
            is not None
            else (
                output_root()
                / "scm"
                / "cache"
                / "gitlab-capabilities.json"
            )
        )
        self.capability_cache = (
            GitLabCapabilityCache(
                selected_cache_path,
                provider_instance=(
                    client.provider_instance
                ),
            )
        )

    def observe(
        self,
        tenant: ScmTenant,
        inventory: RepositoryInventory,
    ) -> ScmObservationResult:
        repositories = active_repositories(
            inventory
        )
        self.capability_cache.load()

        if repositories:
            resources = ordered_parallel_map(
                repositories,
                lambda repository: (
                    read_project_resources(
                        self.client,
                        repository,
                        markers=(
                            self.blackduck_markers
                        ),
                        pipeline_limit=(
                            self.pipeline_limit
                        ),
                        capability_cache=(
                            self.capability_cache
                        ),
                    )
                ),
                workers=min(
                    bounded_worker_count(
                        self.workers,
                        maximum=8,
                    ),
                    len(repositories),
                ),
                maximum=8,
            )
        else:
            resources = []

        self.capability_cache.save()
        evidence_observations = []
        evidence_failures = []
        control_observations = []
        control_failures = []

        for resource in resources:
            evidence = evidence_for_resources(
                tenant,
                resource,
            )
            controls = controls_for_resources(
                tenant,
                resource,
            )
            evidence_observations.extend(
                evidence.observations
            )
            evidence_failures.extend(
                evidence.failures
            )
            control_observations.extend(
                controls.observations
            )
            control_failures.extend(
                controls.failures
            )

        return ScmObservationResult(
            evidence=EvidenceInventory(
                observations=tuple(
                    evidence_observations
                ),
                failures=tuple(
                    evidence_failures
                ),
            ),
            controls=ControlInventory(
                observations=tuple(
                    control_observations
                ),
                failures=tuple(
                    control_failures
                ),
            ),
        )
