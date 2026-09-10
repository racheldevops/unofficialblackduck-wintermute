from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.ai.models import stable_digest
from wintermute.ai.storage import sha256_file


class BatchOnboardingArtifactError(
    RuntimeError
):
    pass


@dataclass(frozen=True)
class LoadedBatchOnboardingPlan:
    directory: Path
    plan: dict[str, Any]
    registry: dict[str, Any]
    github_plan: dict[str, Any] | None
    github_ruleset: dict[str, Any] | None
    gitlab_plan: dict[str, Any] | None
    gitlab_policy: str | None
    digest: str


def read_object(
    path: Path,
) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise BatchOnboardingArtifactError(
            f"Could not read onboarding batch "
            f"artifact {path}: {error}"
        ) from error

    if not isinstance(value, dict):
        raise BatchOnboardingArtifactError(
            f"Onboarding batch artifact is not "
            f"an object: {path}"
        )

    return value


def load_verified_batch_plan(
    directory: str | Path,
) -> LoadedBatchOnboardingPlan:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise BatchOnboardingArtifactError(
            f"Onboarding batch plan does not "
            f"exist: {root}"
        )

    ready = read_object(root / "READY")
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise BatchOnboardingArtifactError(
            "Onboarding batch checksums "
            "are invalid"
        )

    plan = read_object(root / "plan.json")
    registry = read_object(
        root / "scan-profile-registry.json"
    )
    providers = plan.get("providers")

    if (
        not isinstance(providers, list)
        or not providers
        or not all(
            value in {
                "github",
                "gitlab",
            }
            for value in providers
        )
        or providers != sorted(
            set(providers)
        )
    ):
        raise BatchOnboardingArtifactError(
            "Onboarding providers are invalid"
        )

    names = [
        "plan.json",
        "scan-profile-registry.json",
    ]

    if "github" in providers:
        names.extend(
            [
                "github-plan.json",
                "github-ruleset.json",
            ]
        )

    if "gitlab" in providers:
        names.extend(
            [
                "gitlab-plan.json",
                "gitlab-policy.yml",
            ]
        )

    for name in names:
        expected = str(
            checksums.get(name) or ""
        )

        if not expected:
            raise BatchOnboardingArtifactError(
                f"Missing checksum for {name}"
            )

        try:
            actual = sha256_file(root / name)
        except OSError as error:
            raise BatchOnboardingArtifactError(
                f"Could not read {name}: {error}"
            ) from error

        if actual != expected:
            raise BatchOnboardingArtifactError(
                f"Checksum mismatch for {name}"
            )

    plan_id = str(
        plan.get("plan_id") or ""
    )

    if not plan_id:
        raise BatchOnboardingArtifactError(
            "Onboarding plan has no plan ID"
        )

    if ready.get("plan_id") != plan_id:
        raise BatchOnboardingArtifactError(
            "READY marker does not match "
            "the onboarding plan"
        )

    if plan.get("status") != (
        "review-required"
    ):
        raise BatchOnboardingArtifactError(
            "Onboarding plan is not reviewable"
        )

    if plan.get("mutation_allowed") is not False:
        raise BatchOnboardingArtifactError(
            "Planning artifact unexpectedly "
            "allows mutation"
        )

    if (
        registry.get(
            "source_batch_digest"
        )
        != plan.get(
            "source_batch_digest"
        )
    ):
        raise BatchOnboardingArtifactError(
            "Source batch digest does not match"
        )

    assignments = registry.get(
        "assignments"
    )

    if (
        not isinstance(assignments, list)
        or not all(
            isinstance(value, dict)
            for value in assignments
        )
    ):
        raise BatchOnboardingArtifactError(
            "Onboarding assignments are invalid"
        )

    external_ids: set[str] = set()

    for value in assignments:
        external_id = str(
            value.get(
                "repository_external_id"
            )
            or ""
        )

        if (
            not external_id
            or external_id in external_ids
        ):
            raise BatchOnboardingArtifactError(
                "Onboarding assignments contain "
                "invalid repository identities"
            )

        external_ids.add(external_id)

    if plan.get("repository_count") != len(
        assignments
    ):
        raise BatchOnboardingArtifactError(
            "Repository count does not match "
            "the assignments"
        )

    github_plan = (
        read_object(
            root / "github-plan.json"
        )
        if "github" in providers
        else None
    )
    github_ruleset = (
        read_object(
            root / "github-ruleset.json"
        )
        if "github" in providers
        else None
    )
    gitlab_plan = (
        read_object(
            root / "gitlab-plan.json"
        )
        if "gitlab" in providers
        else None
    )
    gitlab_policy = None

    if "gitlab" in providers:
        try:
            gitlab_policy = (
                root / "gitlab-policy.yml"
            ).read_text(encoding="utf-8")
        except OSError as error:
            raise BatchOnboardingArtifactError(
                "Could not read GitLab policy: "
                f"{error}"
            ) from error

    if github_ruleset is not None:
        if (
            github_ruleset.get(
                "enforcement"
            )
            != "evaluate"
            or github_ruleset.get(
                "bypass_actors"
            )
            != []
        ):
            raise BatchOnboardingArtifactError(
                "GitHub ruleset is not safely "
                "staged in evaluate mode"
            )

    if (
        gitlab_policy is not None
        and "enabled: false"
        not in gitlab_policy
    ):
        raise BatchOnboardingArtifactError(
            "GitLab policy is not disabled"
        )

    digest = stable_digest(
        {
            "plan": plan,
            "registry": registry,
            "github_plan": github_plan,
            "github_ruleset": (
                github_ruleset
            ),
            "gitlab_plan": gitlab_plan,
            "gitlab_policy": gitlab_policy,
        }
    )

    return LoadedBatchOnboardingPlan(
        directory=root,
        plan=plan,
        registry=registry,
        github_plan=github_plan,
        github_ruleset=github_ruleset,
        gitlab_plan=gitlab_plan,
        gitlab_policy=gitlab_policy,
        digest=digest,
    )
