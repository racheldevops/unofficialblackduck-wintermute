from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wintermute.ai.models import (
    stable_digest,
)
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)


ARTIFACT_NAMES = (
    "plan.json",
    "profile-registry.json",
)


class OnboardingArtifactError(
    RuntimeError
):
    pass


@dataclass(frozen=True)
class LoadedOnboardingPlan:
    directory: Path
    plan: dict[str, Any]
    registry: dict[str, Any]
    provider_policy: (
        dict[str, Any] | str
    )
    provider_policy_name: str
    digest: str


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def read_object(
    path: Path,
) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise OnboardingArtifactError(
            "Could not read onboarding "
            f"artifact {path}: {error}"
        ) from error

    if not isinstance(value, dict):
        raise OnboardingArtifactError(
            "Onboarding artifact is not "
            f"an object: {path}"
        )

    return value


def load_verified_plan(
    directory: str | Path,
) -> LoadedOnboardingPlan:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise OnboardingArtifactError(
            "Onboarding plan does not "
            f"exist: {root}"
        )

    ready = read_object(
        root / "READY"
    )
    plan = read_object(
        root / "plan.json"
    )
    registry = read_object(
        root / "profile-registry.json"
    )
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise OnboardingArtifactError(
            "Onboarding checksums are invalid"
        )

    repository = plan.get("repository")

    if not isinstance(repository, dict):
        raise OnboardingArtifactError(
            "Onboarding repository is invalid"
        )

    provider = str(
        repository.get("provider") or ""
    )

    if provider == "github":
        policy_name = (
            "provider-policy.json"
        )
    elif provider == "gitlab":
        policy_name = (
            "provider-policy.yml"
        )
    else:
        raise OnboardingArtifactError(
            "Onboarding provider is invalid"
        )

    artifact_names = (
        *ARTIFACT_NAMES,
        policy_name,
    )

    for name in artifact_names:
        expected = str(
            checksums.get(name) or ""
        )

        if not expected:
            raise OnboardingArtifactError(
                f"Missing checksum for {name}"
            )

        try:
            actual = sha256_file(
                root / name
            )
        except OSError as error:
            raise OnboardingArtifactError(
                f"Could not read {name}: "
                f"{error}"
            ) from error

        if actual != expected:
            raise OnboardingArtifactError(
                f"Checksum mismatch for {name}"
            )

    plan_id = str(
        plan.get("plan_id") or ""
    )

    if not plan_id:
        raise OnboardingArtifactError(
            "Onboarding plan has no plan ID"
        )

    if ready.get("plan_id") != plan_id:
        raise OnboardingArtifactError(
            "READY marker does not match "
            "the plan"
        )

    if plan.get("status") != (
        "review-required"
    ):
        raise OnboardingArtifactError(
            "Onboarding plan is not "
            "reviewable"
        )

    if (
        plan.get("mutation_allowed")
        is not False
    ):
        raise OnboardingArtifactError(
            "Onboarding plan has an invalid "
            "planning mutation state"
        )

    if (
        registry.get("repository")
        != repository
    ):
        raise OnboardingArtifactError(
            "Profile registry repository "
            "does not match the plan"
        )

    analysis = registry.get("analysis")

    if not isinstance(analysis, dict):
        raise OnboardingArtifactError(
            "Profile registry analysis "
            "is invalid"
        )

    if (
        analysis.get("analysis_digest")
        != plan.get("analysis_digest")
    ):
        raise OnboardingArtifactError(
            "Analysis digest does not match "
            "the profile registry"
        )

    if provider == "github":
        provider_policy: (
            dict[str, Any] | str
        ) = read_object(
            root / policy_name
        )
    else:
        try:
            provider_policy = (
                root / policy_name
            ).read_text(
                encoding="utf-8"
            )
        except OSError as error:
            raise OnboardingArtifactError(
                f"Could not read {policy_name}: "
                f"{error}"
            ) from error

        if (
            "enabled: false"
            not in provider_policy
        ):
            raise OnboardingArtifactError(
                "GitLab policy is not disabled"
            )

    digest = stable_digest(
        {
            "plan": plan,
            "registry": registry,
            "provider_policy": (
                provider_policy
            ),
        }
    )

    return LoadedOnboardingPlan(
        directory=root,
        plan=plan,
        registry=registry,
        provider_policy=(
            provider_policy
        ),
        provider_policy_name=(
            policy_name
        ),
        digest=digest,
    )


def byte_reference(
    value: bytes,
) -> dict[str, Any]:
    return {
        "representation": (
            "sha256-reference"
        ),
        "sha256": hashlib.sha256(
            value
        ).hexdigest(),
        "size": len(value),
    }


def artifact_safe(
    value: Any,
) -> Any:
    if value is None or isinstance(
        value,
        (str, int, float, bool),
    ):
        return value

    if isinstance(
        value,
        (bytes, bytearray),
    ):
        return byte_reference(
            bytes(value)
        )

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        result: dict[str, Any] = {}

        for key, nested in value.items():
            if not isinstance(key, str):
                raise TypeError(
                    "Execution artifact object "
                    "keys must be strings"
                )

            result[key] = artifact_safe(
                nested
            )

        return result

    if isinstance(
        value,
        (list, tuple),
    ):
        return [
            artifact_safe(nested)
            for nested in value
        ]

    raise TypeError(
        "Execution artifact contains an "
        "unsupported value type: "
        f"{type(value).__name__}"
    )


def write_execution_result(
    root: str | Path,
    result: dict[str, Any],
) -> Path:
    result_id = str(
        result.get("execution_id") or ""
    )

    if not result_id:
        raise ValueError(
            "Execution result has no ID"
        )

    root_path = Path(root)
    staging = (
        root_path
        / ".staging"
        / result_id
    )
    destination = (
        root_path / result_id
    )

    if destination.exists():
        raise RuntimeError(
            "Execution result already "
            f"exists: {destination}"
        )

    if staging.exists():
        shutil.rmtree(
            staging
        )

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )
    safe_result = artifact_safe(
        result
    )

    if not isinstance(
        safe_result,
        dict,
    ):
        raise TypeError(
            "Execution result must be "
            "an object"
        )

    try:
        atomic_write_json(
            staging / "result.json",
            safe_result,
        )
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    "result.json": (
                        sha256_file(
                            staging
                            / "result.json"
                        )
                    )
                },
            },
        )
        root_path.mkdir(
            parents=True,
            exist_ok=True,
        )
        os.replace(
            staging,
            destination,
        )
        atomic_write_json(
            destination / "READY",
            {
                "schema_version": 1,
                "execution_id": (
                    result_id
                ),
                "ready_at": now_text(),
            },
        )

        return destination

    except BaseException:
        shutil.rmtree(
            staging,
            ignore_errors=True,
        )
        raise


def create_execution_id() -> str:
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    return (
        f"{timestamp}-scan-onboarding-"
        f"{uuid.uuid4().hex[:12]}"
    )
