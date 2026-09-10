from __future__ import annotations

import argparse
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.ai.artifacts import (
    load_verified_analysis,
)
from wintermute.ai.config import (
    AISettings,
    load_ai_settings,
)
from wintermute.ai.gateway import AIGateway
from wintermute.ai.models import (
    stable_digest,
)
from wintermute.ai.provider import (
    OpenAICompatibleProvider,
)
from wintermute.ai.safety import (
    Anonymizer,
    Sanitizer,
)
from wintermute.ai.scm_evidence import (
    build_lazy_remote_catalog,
)
from wintermute.ai.scm_profile import (
    all_repositories,
    source_for_repository,
)
from wintermute.ai.storage import (
    AIResponseCache,
    AIUsageLedger,
    atomic_write_json,
    now_text,
    sha256_file,
    write_analysis,
)
from wintermute.file_lock import FileLock
from wintermute.paths import output_root
from wintermute.scm.inventory import (
    repository_payload,
)
from wintermute.scm.models import Repository
from wintermute.scm.snapshots import (
    LoadedInventorySnapshot,
    load_inventory_snapshot,
)


STATE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class RepositoryWork:
    snapshot: LoadedInventorySnapshot
    repository: Repository


def batch_id() -> str:
    return (
        time.strftime(
            "%Y%m%dT%H%M%SZ",
            time.gmtime(),
        )
        + "-scm-scan-profiles-"
        + uuid.uuid4().hex[:12]
    )


def latest_snapshots(
    root: Path,
    *,
    providers: set[str],
) -> tuple[LoadedInventorySnapshot, ...]:
    if not root.is_dir():
        raise ValueError(
            f"SCM snapshot root does not exist: "
            f"{root}"
        )

    selected: dict[
        str,
        LoadedInventorySnapshot,
    ] = {}

    for path in sorted(
        root.iterdir(),
        key=lambda value: value.name,
        reverse=True,
    ):
        if (
            not path.is_dir()
            or not (
                path / "READY"
            ).is_file()
        ):
            continue

        try:
            snapshot = (
                load_inventory_snapshot(path)
            )
        except Exception:
            continue

        if (
            providers
            and snapshot.tenant.provider
            not in providers
        ):
            continue

        selected.setdefault(
            snapshot.tenant.external_id,
            snapshot,
        )

    if not selected:
        raise ValueError(
            "No matching ready SCM snapshots "
            "were found"
        )

    return tuple(
        sorted(
            selected.values(),
            key=lambda value: (
                value.tenant.provider,
                value.tenant
                .provider_instance,
                value.tenant.namespace,
            ),
        )
    )


def resolve_snapshots(
    args: argparse.Namespace,
) -> tuple[LoadedInventorySnapshot, ...]:
    if args.scm_snapshot:
        snapshots = tuple(
            load_inventory_snapshot(path)
            for path in args.scm_snapshot
        )
    else:
        snapshots = latest_snapshots(
            (
                output_root()
                / "scm"
                / "inventory"
                / "snapshots"
            ),
            providers=set(
                args.scm_provider
            ),
        )

    if args.scm_provider:
        unexpected = {
            snapshot.tenant.provider
            for snapshot in snapshots
            if snapshot.tenant.provider
            not in set(args.scm_provider)
        }

        if unexpected:
            raise ValueError(
                "SCM snapshot provider was not "
                "selected: "
                + ", ".join(
                    sorted(unexpected)
                )
            )

    return snapshots


def repository_scope(
    snapshots: tuple[
        LoadedInventorySnapshot,
        ...
    ],
    *,
    names: set[str],
    include_excluded: bool,
) -> tuple[RepositoryWork, ...]:
    values: dict[
        str,
        RepositoryWork,
    ] = {}

    for snapshot in snapshots:
        for repository in all_repositories(
            snapshot,
            include_excluded=(
                include_excluded
            ),
        ):
            if (
                names
                and repository
                .name_with_owner
                .casefold()
                not in names
            ):
                continue

            values[
                repository.external_id
            ] = RepositoryWork(
                snapshot=snapshot,
                repository=repository,
            )

    if names:
        found = {
            value.repository
            .name_with_owner
            .casefold()
            for value in values.values()
        }
        missing = names - found

        if missing:
            raise ValueError(
                "Repository selection was not "
                "found in the SCM snapshots: "
                + ", ".join(sorted(missing))
            )

    if not values:
        raise ValueError(
            "No repositories matched the "
            "batch selection"
        )

    return tuple(
        sorted(
            values.values(),
            key=lambda value: (
                value.repository.provider,
                value.repository
                .provider_instance,
                value.repository
                .name_with_owner
                .casefold(),
                value.repository.repository_id,
            ),
        )
    )


def settings_fingerprint(
    settings: AISettings,
) -> str:
    return stable_digest(
        {
            "provider": settings.provider,
            "model": settings.model,
            "endpoint": settings.endpoint,
            "deployment": settings.deployment,
            "max_rounds": (
                settings.max_rounds
            ),
            "max_catalog_files": (
                settings.max_catalog_files
            ),
            "max_evidence_files": (
                settings.max_evidence_files
            ),
            "max_evidence_bytes": (
                settings.max_evidence_bytes
            ),
            "max_file_bytes": (
                settings.max_file_bytes
            ),
            "allow_source": (
                settings.allow_source
            ),
            "task": "scm.scan-profile",
            "task_version": "1",
        }
    )


def repository_fingerprint(
    work: RepositoryWork,
    settings: AISettings,
) -> str:
    repository = work.repository

    return stable_digest(
        {
            "repository_external_id": (
                repository.external_id
            ),
            "head_sha": repository.head_sha,
            "default_branch": (
                repository.default_branch
            ),
            "snapshot_id": (
                work.snapshot.snapshot_id
                if not repository.head_sha
                else ""
            ),
            "settings": (
                settings_fingerprint(settings)
            ),
        }
    )


def fresh_state() -> dict[str, Any]:
    return {
        "schema_version": (
            STATE_SCHEMA_VERSION
        ),
        "entries": {},
    }


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return fresh_state()

    try:
        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise RuntimeError(
            f"Could not read batch state: "
            f"{error}"
        ) from error

    if (
        not isinstance(payload, dict)
        or payload.get("schema_version")
        != STATE_SCHEMA_VERSION
        or not isinstance(
            payload.get("entries"),
            dict,
        )
    ):
        raise RuntimeError(
            "AI batch state is invalid"
        )

    return payload


def reusable_analysis(
    state: dict[str, Any],
    work: RepositoryWork,
    settings: AISettings,
) -> Any | None:
    entry = state["entries"].get(
        work.repository.external_id
    )

    if not isinstance(entry, dict):
        return None

    if entry.get("fingerprint") != (
        repository_fingerprint(
            work,
            settings,
        )
    ):
        return None

    path = str(
        entry.get("analysis_directory")
        or ""
    )

    if not path:
        return None

    try:
        return load_verified_analysis(path)
    except Exception:
        return None


def profile_group_key(
    profile: dict[str, Any],
) -> str:
    return stable_digest(
        {
            "central_template": (
                profile.get(
                    "central_template"
                )
            ),
            "scan_mode": profile.get(
                "scan_mode"
            ),
            "build_systems": sorted(
                profile.get(
                    "build_systems",
                    [],
                )
            ),
            "package_managers": sorted(
                profile.get(
                    "package_managers",
                    [],
                )
            ),
            "parameters": profile.get(
                "parameters",
                {},
            ),
        }
    )


def build_registry(
    profiles: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered = sorted(
        profiles,
        key=lambda value: (
            value["repository"]["provider"],
            value["repository"][
                "provider_instance"
            ],
            value["repository"][
                "name_with_owner"
            ].casefold(),
            value["repository"][
                "repository_id"
            ],
        ),
    )
    grouped: dict[
        str,
        list[str],
    ] = {}

    for value in ordered:
        key = profile_group_key(
            value["scan_profile"]
        )
        value["profile_group_key"] = key
        grouped.setdefault(
            key,
            [],
        ).append(
            value["repository"][
                "external_id"
            ]
        )

    return {
        "schema_version": 1,
        "profile_count": len(ordered),
        "profile_group_count": len(
            grouped
        ),
        "profiles": ordered,
        "groups": [
            {
                "profile_group_key": key,
                "repository_external_ids": (
                    sorted(grouped[key])
                ),
            }
            for key in sorted(grouped)
        ],
    }


def profile_entry(
    work: RepositoryWork,
    analysis: Any,
    *,
    reused: bool,
    scm_requests: int,
    catalog_file_count: int,
    retrieved_file_count: int,
    retrieved_byte_count: int,
) -> dict[str, Any]:
    return {
        "repository": repository_payload(
            work.repository
        ),
        "source_snapshot_id": (
            work.snapshot.snapshot_id
        ),
        "analysis_id": (
            analysis.analysis["analysis_id"]
        ),
        "analysis_digest": (
            analysis.digest
        ),
        "analysis_directory": str(
            analysis.directory
        ),
        "scan_profile": (
            analysis.analysis["result"]
        ),
        "reused": reused,
        "scm_requests": scm_requests,
        "catalog_file_count": (
            catalog_file_count
        ),
        "retrieved_file_count": (
            retrieved_file_count
        ),
        "retrieved_byte_count": (
            retrieved_byte_count
        ),
    }


def write_batch(
    root: Path,
    identifier: str,
    registry: dict[str, Any],
    failures: list[dict[str, Any]],
    summary: dict[str, Any],
) -> Path:
    staging = (
        root / ".staging" / identifier
    )
    destination = root / identifier

    if destination.exists():
        raise RuntimeError(
            f"AI batch already exists: "
            f"{destination}"
        )

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )
    names = (
        "profile-registry.json",
        "failures.json",
        "summary.json",
    )

    try:
        atomic_write_json(
            staging
            / "profile-registry.json",
            registry,
        )
        atomic_write_json(
            staging / "failures.json",
            {
                "schema_version": 1,
                "failure_count": len(
                    failures
                ),
                "failures": failures,
            },
        )
        atomic_write_json(
            staging / "summary.json",
            summary,
        )
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    name: sha256_file(
                        staging / name
                    )
                    for name in names
                },
            },
        )
        root.mkdir(
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
                "batch_id": identifier,
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


def run(
    args: argparse.Namespace,
) -> int:
    validate_args(args)
    settings = load_ai_settings(
        provider=args.provider,
        model=args.model,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
    )
    snapshots = resolve_snapshots(args)
    work_items = repository_scope(
        snapshots,
        names={
            value.casefold()
            for value in args.repository
        },
        include_excluded=(
            args.include_excluded
        ),
    )
    ai_root = Path(
        args.output_root
    ).expanduser()
    state_path = (
        ai_root
        / "state"
        / "scm-batch.json"
    )
    lock_path = (
        ai_root
        / "state"
        / "scm-batch.lock"
    )
    cache = AIResponseCache(
        ai_root
        / "state"
        / "responses.sqlite3"
    )
    ledger = AIUsageLedger(
        ai_root
        / "state"
        / "usage.sqlite3"
    )
    provider = OpenAICompatibleProvider(
        settings
    )
    gateway = AIGateway(
        settings,
        provider,
        cache,
        ledger,
    )
    anonymizer = Anonymizer(
        settings.anonymization_key
        or "local-vllm-only"
    )
    sanitizer = Sanitizer(anonymizer)
    identifier = batch_id()
    started = time.monotonic()
    deadline = (
        started
        + args.max_minutes * 60
    )
    profiles: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    reused_count = 0
    processed_count = 0
    deferred_count = 0

    with FileLock(
        lock_path,
        stale_seconds=7200,
        wait_seconds=0,
    ):
        state = (
            fresh_state()
            if args.refresh
            else load_state(state_path)
        )
        pending: list[RepositoryWork] = []

        for work in work_items:
            loaded = reusable_analysis(
                state,
                work,
                settings,
            )

            if loaded is None:
                pending.append(work)
                continue

            profiles.append(
                profile_entry(
                    work,
                    loaded,
                    reused=True,
                    scm_requests=0,
                    catalog_file_count=0,
                    retrieved_file_count=0,
                    retrieved_byte_count=0,
                )
            )
            reused_count += 1

        selected_pending = pending[
            :args.max_repositories
        ]
        deferred_count = (
            len(pending)
            - len(selected_pending)
        )

        for index, work in enumerate(
            selected_pending,
            start=1,
        ):
            repository = work.repository
            print(
                "AI scan-profile batch: "
                f"{index}/{len(selected_pending)} "
                f"{repository.provider} "
                f"{repository.name_with_owner}",
                file=__import__("sys").stderr,
            )

            try:
                source = source_for_repository(
                    repository,
                    args,
                    deadline=deadline,
                )
                lazy_catalog = (
                    build_lazy_remote_catalog(
                        source,
                        sanitizer,
                        max_catalog_files=min(
                            args.max_remote_files,
                            settings
                            .max_catalog_files,
                        ),
                        max_file_bytes=(
                            settings.max_file_bytes
                        ),
                        max_total_bytes=(
                            args.max_remote_bytes
                        ),
                    )
                )
                result = gateway.scan_profile(
                    lazy_catalog,
                    repository_alias=(
                        anonymizer.alias(
                            "repository",
                            repository.external_id,
                        )
                    ),
                    tenant_alias=(
                        anonymizer.alias(
                            "tenant",
                            work.snapshot
                            .tenant.external_id,
                        )
                    ),
                )
                directory = write_analysis(
                    ai_root / "analyses",
                    result,
                    evidence_catalog=(
                        lazy_catalog
                        .private_descriptor_payload()
                    ),
                )
                loaded = (
                    load_verified_analysis(
                        directory
                    )
                )
                profiles.append(
                    profile_entry(
                        work,
                        loaded,
                        reused=False,
                        scm_requests=(
                            source.request_count
                        ),
                        catalog_file_count=(
                            lazy_catalog
                            .listed_file_count
                        ),
                        retrieved_file_count=(
                            lazy_catalog
                            .selected_file_count
                        ),
                        retrieved_byte_count=(
                            lazy_catalog
                            .retrieved_byte_count
                        ),
                    )
                )
                state["entries"][
                    repository.external_id
                ] = {
                    "fingerprint": (
                        repository_fingerprint(
                            work,
                            settings,
                        )
                    ),
                    "analysis_id": (
                        result.analysis_id
                    ),
                    "analysis_directory": (
                        str(directory)
                    ),
                    "snapshot_id": (
                        work.snapshot.snapshot_id
                    ),
                    "updated_at": now_text(),
                }
                atomic_write_json(
                    state_path,
                    state,
                )
                processed_count += 1

            except Exception as error:
                failures.append(
                    {
                        "provider": (
                            repository.provider
                        ),
                        "provider_instance": (
                            repository
                            .provider_instance
                        ),
                        "repository_external_id": (
                            repository.external_id
                        ),
                        "name_with_owner": (
                            repository
                            .name_with_owner
                        ),
                        "stage": (
                            "generate-scan-profile"
                        ),
                        "error": str(error),
                    }
                )

        registry = build_registry(
            profiles
        )
        status = (
            "partial"
            if failures
            else "succeeded"
        )
        summary = {
            "schema_version": 1,
            "batch_id": identifier,
            "created_at": now_text(),
            "status": status,
            "snapshot_ids": sorted(
                snapshot.snapshot_id
                for snapshot in snapshots
            ),
            "selected_repository_count": (
                len(work_items)
            ),
            "processed_repository_count": (
                processed_count
            ),
            "reused_repository_count": (
                reused_count
            ),
            "deferred_repository_count": (
                deferred_count
            ),
            "profile_count": len(profiles),
            "profile_group_count": (
                registry[
                    "profile_group_count"
                ]
            ),
            "failure_count": len(failures),
            "usage": ledger.summary(),
            "elapsed_seconds": round(
                time.monotonic()
                - started,
                3,
            ),
        }
        directory = write_batch(
            ai_root / "batches",
            identifier,
            registry,
            failures,
            summary,
        )

    print(
        json.dumps(
            {
                **summary,
                "batch_directory": (
                    str(directory)
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 1 if failures else 0


def add_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    environment_snapshot = os.getenv(
        "SCM_INVENTORY_SNAPSHOT",
        "",
    ).strip()
    parser.add_argument(
        "--scm-snapshot",
        action="append",
        default=(
            [environment_snapshot]
            if environment_snapshot
            else []
        ),
    )
    parser.add_argument(
        "--scm-provider",
        action="append",
        choices=[
            "github",
            "gitlab",
        ],
        default=[],
    )
    parser.add_argument(
        "--repository",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--include-excluded",
        action="store_true",
    )
    parser.add_argument(
        "--provider",
        choices=["azure", "vllm"],
        default="",
    )
    parser.add_argument(
        "--model",
        default="",
    )
    parser.add_argument(
        "--max-repositories",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--max-remote-files",
        type=int,
        default=2000,
    )
    parser.add_argument(
        "--max-remote-bytes",
        type=int,
        default=2 * 1024 * 1024,
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
    )
    parser.add_argument(
        "--max-minutes",
        type=float,
        default=60,
    )
    parser.add_argument(
        "--scm-timeout",
        type=float,
        default=30,
    )
    parser.add_argument(
        "--scm-retries",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--scm-retry-delay",
        type=float,
        default=1,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument(
        "--ca-bundle",
    )


def validate_args(
    args: argparse.Namespace,
) -> None:
    for name in (
        "max_repositories",
        "max_remote_files",
        "max_remote_bytes",
    ):
        if int(getattr(args, name)) < 1:
            raise ValueError(
                f"--{name.replace('_', '-')} "
                "must be positive"
            )

    if args.max_minutes <= 0:
        raise ValueError(
            "--max-minutes must be positive"
        )

    if args.scm_timeout <= 0:
        raise ValueError(
            "--scm-timeout must be positive"
        )

    if args.scm_retries < 0:
        raise ValueError(
            "--scm-retries cannot be negative"
        )

    if args.scm_retry_delay < 0:
        raise ValueError(
            "--scm-retry-delay cannot be negative"
        )
