from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.ai.models import stable_digest
from wintermute.ai.storage import sha256_file


ARTIFACT_NAMES = (
    "profile-registry.json",
    "failures.json",
    "summary.json",
)


class BatchArtifactError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedProfileBatch:
    directory: Path
    batch_id: str
    registry: dict[str, Any]
    failures: tuple[dict[str, Any], ...]
    summary: dict[str, Any]
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
        raise BatchArtifactError(
            f"Could not read AI batch artifact "
            f"{path}: {error}"
        ) from error

    if not isinstance(value, dict):
        raise BatchArtifactError(
            f"AI batch artifact is not an "
            f"object: {path}"
        )

    return value


def load_verified_profile_batch(
    directory: str | Path,
    *,
    allow_failures: bool = False,
) -> LoadedProfileBatch:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise BatchArtifactError(
            f"AI profile batch does not exist: "
            f"{root}"
        )

    ready = read_object(root / "READY")
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise BatchArtifactError(
            "AI batch checksums are invalid"
        )

    for name in ARTIFACT_NAMES:
        expected = str(
            checksums.get(name) or ""
        )

        if not expected:
            raise BatchArtifactError(
                f"Missing checksum for {name}"
            )

        try:
            actual = sha256_file(root / name)
        except OSError as error:
            raise BatchArtifactError(
                f"Could not read {name}: {error}"
            ) from error

        if actual != expected:
            raise BatchArtifactError(
                f"Checksum mismatch for {name}"
            )

    registry = read_object(
        root / "profile-registry.json"
    )
    failures_payload = read_object(
        root / "failures.json"
    )
    summary = read_object(
        root / "summary.json"
    )
    batch_id = str(
        summary.get("batch_id") or ""
    )

    if not batch_id:
        raise BatchArtifactError(
            "AI batch has no batch ID"
        )

    if ready.get("batch_id") != batch_id:
        raise BatchArtifactError(
            "AI batch READY marker does not "
            "match the summary"
        )

    profiles = registry.get("profiles")
    groups = registry.get("groups")
    raw_failures = failures_payload.get(
        "failures"
    )

    if (
        not isinstance(profiles, list)
        or not all(
            isinstance(value, dict)
            for value in profiles
        )
    ):
        raise BatchArtifactError(
            "AI profile registry profiles "
            "are invalid"
        )

    if (
        not isinstance(groups, list)
        or not all(
            isinstance(value, dict)
            for value in groups
        )
    ):
        raise BatchArtifactError(
            "AI profile registry groups "
            "are invalid"
        )

    if (
        not isinstance(raw_failures, list)
        or not all(
            isinstance(value, dict)
            for value in raw_failures
        )
    ):
        raise BatchArtifactError(
            "AI batch failures are invalid"
        )

    failures = tuple(
        dict(value)
        for value in raw_failures
    )

    if (
        failures_payload.get(
            "failure_count"
        )
        != len(failures)
    ):
        raise BatchArtifactError(
            "AI batch failure count does not "
            "match its records"
        )

    if failures and not allow_failures:
        raise BatchArtifactError(
            "AI batch contains failures"
        )

    if registry.get("profile_count") != len(
        profiles
    ):
        raise BatchArtifactError(
            "AI profile count does not match "
            "the registry"
        )

    repository_ids: set[str] = set()
    grouped_ids: set[str] = set()

    for profile in profiles:
        repository = profile.get(
            "repository"
        )
        scan_profile = profile.get(
            "scan_profile"
        )
        group_key = str(
            profile.get(
                "profile_group_key"
            )
            or ""
        )

        if not isinstance(repository, dict):
            raise BatchArtifactError(
                "AI batch repository is invalid"
            )

        if not isinstance(scan_profile, dict):
            raise BatchArtifactError(
                "AI batch scan profile is invalid"
            )

        external_id = str(
            repository.get("external_id")
            or ""
        )

        if not external_id:
            raise BatchArtifactError(
                "AI batch repository has no "
                "external ID"
            )

        if external_id in repository_ids:
            raise BatchArtifactError(
                "AI batch contains a duplicate "
                "repository"
            )

        if not group_key:
            raise BatchArtifactError(
                "AI batch profile has no group key"
            )

        repository_ids.add(external_id)

    for group in groups:
        group_key = str(
            group.get(
                "profile_group_key"
            )
            or ""
        )
        members = group.get(
            "repository_external_ids"
        )

        if (
            not group_key
            or not isinstance(members, list)
            or not all(
                isinstance(value, str)
                and value
                for value in members
            )
        ):
            raise BatchArtifactError(
                "AI batch profile group is invalid"
            )

        for external_id in members:
            if external_id in grouped_ids:
                raise BatchArtifactError(
                    "Repository appears in more than "
                    "one AI profile group"
                )

            grouped_ids.add(external_id)

    if grouped_ids != repository_ids:
        raise BatchArtifactError(
            "AI profile groups do not reconcile "
            "with repositories"
        )

    if registry.get(
        "profile_group_count"
    ) != len(groups):
        raise BatchArtifactError(
            "AI profile-group count does not "
            "match the registry"
        )

    digest = stable_digest(
        {
            "registry": registry,
            "failures": failures,
            "summary": summary,
        }
    )

    return LoadedProfileBatch(
        directory=root,
        batch_id=batch_id,
        registry=registry,
        failures=failures,
        summary=summary,
        digest=digest,
    )
