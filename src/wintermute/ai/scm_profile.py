from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from wintermute.ai.config import (
    load_ai_settings,
)
from wintermute.ai.gateway import AIGateway
from wintermute.ai.provider import (
    OpenAICompatibleProvider,
)
from wintermute.ai.safety import (
    Anonymizer,
    Sanitizer,
)
from wintermute.ai.scm_evidence import (
    GitHubEvidenceSource,
    GitLabEvidenceSource,
    RemoteCatalogResult,
    build_remote_catalog,
)
from wintermute.ai.storage import (
    AIResponseCache,
    AIUsageLedger,
    write_analysis,
)
from wintermute.file_lock import FileLock
from wintermute.paths import output_root
from wintermute.scm.models import (
    Repository,
)
from wintermute.scm.providers.gitlab.client import (
    DEFAULT_REST_BASE_URL as DEFAULT_GITLAB_REST_URL,
)
from wintermute.scm.snapshots import (
    LoadedInventorySnapshot,
    load_inventory_snapshot,
)


def all_repositories(
    snapshot: LoadedInventorySnapshot,
    *,
    include_excluded: bool,
) -> tuple[Repository, ...]:
    repositories = list(
        snapshot.inventory.repositories
    )

    if include_excluded:
        repositories.extend(
            value.repository
            for value
            in snapshot.inventory.exclusions
        )

    return tuple(repositories)


def select_repository(
    snapshot: LoadedInventorySnapshot,
    *,
    repository_external_id: str = "",
    name_with_owner: str = "",
    include_excluded: bool = False,
) -> Repository:
    repositories = all_repositories(
        snapshot,
        include_excluded=include_excluded,
    )
    selected_id = str(
        repository_external_id or ""
    ).strip()
    selected_name = str(
        name_with_owner or ""
    ).strip().casefold()

    if not selected_id and not selected_name:
        raise ValueError(
            "Repository external ID or exact "
            "name_with_owner is required"
        )

    matches = [
        repository
        for repository in repositories
        if (
            selected_id
            and repository.external_id
            == selected_id
        )
        or (
            selected_name
            and repository.name_with_owner
            .casefold()
            == selected_name
        )
    ]

    if not matches:
        raise ValueError(
            "Repository was not found in the "
            "SCM snapshot"
        )

    if len(matches) != 1:
        raise ValueError(
            "Repository selection is ambiguous"
        )

    return matches[0]


def latest_snapshot(
    root: Path,
    *,
    provider: str,
    repository_name: str,
    include_excluded: bool,
) -> LoadedInventorySnapshot:
    if not root.is_dir():
        raise ValueError(
            f"SCM snapshot root does not exist: "
            f"{root}"
        )

    candidates = sorted(
        (
            path
            for path in root.iterdir()
            if (
                path.is_dir()
                and (path / "READY").is_file()
            )
        ),
        key=lambda path: path.name,
        reverse=True,
    )
    errors: list[str] = []

    for path in candidates:
        try:
            snapshot = (
                load_inventory_snapshot(path)
            )
        except Exception as error:
            errors.append(
                f"{path.name}: {error}"
            )
            continue

        if (
            provider
            and snapshot.tenant.provider
            != provider
        ):
            continue

        if repository_name:
            names = {
                repository.name_with_owner
                .casefold()
                for repository
                in all_repositories(
                    snapshot,
                    include_excluded=(
                        include_excluded
                    ),
                )
            }

            if (
                repository_name.casefold()
                not in names
            ):
                continue

        return snapshot

    detail = (
        "; ".join(errors[:3])
        if errors
        else "No matching ready snapshots"
    )
    raise ValueError(
        f"Could not select an SCM snapshot: "
        f"{detail}"
    )


def resolve_snapshot(
    args: argparse.Namespace,
) -> LoadedInventorySnapshot:
    if args.scm_snapshot:
        return load_inventory_snapshot(
            args.scm_snapshot
        )

    root = (
        output_root()
        / "scm"
        / "inventory"
        / "snapshots"
    )

    return latest_snapshot(
        root,
        provider=args.scm_provider,
        repository_name=(
            args.repository_name
        ),
        include_excluded=(
            args.include_excluded
        ),
    )


def source_for_repository(
    repository: Repository,
    args: argparse.Namespace,
    *,
    deadline: float,
):
    if repository.provider == "github":
        token = os.getenv(
            "GITHUB_TOKEN",
            "",
        ).strip()

        if not token:
            raise ValueError(
                "GITHUB_TOKEN must be set"
            )

        base_url = (
            os.getenv(
                "GITHUB_REST_URL",
                "",
            ).strip()
            or (
                "https://api.github.com"
                if repository.provider_instance
                == "api.github.com"
                else (
                    "https://"
                    f"{repository.provider_instance}"
                    "/api/v3"
                )
            )
        )

        return GitHubEvidenceSource(
            repository,
            token,
            base_url=base_url,
            timeout=args.scm_timeout,
            retries=args.scm_retries,
            retry_delay=(
                args.scm_retry_delay
            ),
            insecure=args.insecure,
            ca_bundle=args.ca_bundle,
            deadline=deadline,
        )

    if repository.provider == "gitlab":
        token = os.getenv(
            "GITLAB_TOKEN",
            "",
        ).strip()
        base_url = (
            os.getenv(
                "GITLAB_REST_URL",
                "",
            ).strip()
            or (
                "https://"
                f"{repository.provider_instance}"
                "/api/v4"
            )
            or DEFAULT_GITLAB_REST_URL
        )

        return GitLabEvidenceSource(
            repository,
            token,
            base_url=base_url,
            timeout=args.scm_timeout,
            retries=args.scm_retries,
            retry_delay=(
                args.scm_retry_delay
            ),
            insecure=args.insecure,
            ca_bundle=args.ca_bundle,
            deadline=deadline,
        )

    raise ValueError(
        f"Unsupported SCM provider: "
        f"{repository.provider}"
    )


def run(
    args: argparse.Namespace,
) -> int:
    settings = load_ai_settings(
        provider=args.provider,
        model=args.model,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
    )
    snapshot = resolve_snapshot(args)
    repository = select_repository(
        snapshot,
        repository_external_id=(
            args.repository_external_id
        ),
        name_with_owner=(
            args.repository_name
        ),
        include_excluded=(
            args.include_excluded
        ),
    )

    if (
        args.scm_provider
        and repository.provider
        != args.scm_provider
    ):
        raise ValueError(
            "Selected repository provider does "
            "not match --scm-provider"
        )

    deadline = (
        time.monotonic()
        + args.max_minutes * 60
    )
    anonymizer = Anonymizer(
        settings.anonymization_key
        or "local-vllm-only"
    )
    sanitizer = Sanitizer(anonymizer)
    source = source_for_repository(
        repository,
        args,
        deadline=deadline,
    )
    maximum_remote_files = min(
        args.max_remote_files,
        settings.max_catalog_files,
    )
    remote = build_remote_catalog(
        source,
        sanitizer,
        max_catalog_files=(
            maximum_remote_files
        ),
        max_file_bytes=(
            settings.max_file_bytes
        ),
        max_total_bytes=(
            args.max_remote_bytes
        ),
    )

    if (
        remote.failures
        and not args.allow_partial_evidence
    ):
        raise RuntimeError(
            "Remote evidence retrieval failed: "
            + "; ".join(
                remote.failures[:5]
            )
        )

    ai_root = Path(
        args.output_root
    ).expanduser()
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
    repository_alias = anonymizer.alias(
        "repository",
        repository.external_id,
    )
    tenant_alias = anonymizer.alias(
        "tenant",
        snapshot.tenant.external_id,
    )
    lock_path = (
        ai_root
        / "state"
        / "locks"
        / f"{repository.external_id}.lock"
    )

    with FileLock(
        lock_path,
        stale_seconds=7200,
        wait_seconds=0,
    ):
        result = gateway.scan_profile(
            remote.catalog,
            repository_alias=(
                repository_alias
            ),
            tenant_alias=tenant_alias,
        )
        directory = write_analysis(
            ai_root / "analyses",
            result,
            evidence_catalog=(
                remote.catalog
                .private_descriptor_payload()
            ),
        )

    print(
        json.dumps(
            {
                "analysis_id": (
                    result.analysis_id
                ),
                "analysis_directory": (
                    str(directory)
                ),
                "provider": result.provider,
                "model": result.model,
                "scm_provider": (
                    repository.provider
                ),
                "repository_external_id": (
                    repository.external_id
                ),
                "name_with_owner": (
                    repository.name_with_owner
                ),
                "source_snapshot_id": (
                    snapshot.snapshot_id
                ),
                "listed_file_count": (
                    remote.listed_file_count
                ),
                "selected_file_count": (
                    remote.selected_file_count
                ),
                "retrieved_byte_count": (
                    remote.retrieved_byte_count
                ),
                "retrieval_failure_count": (
                    len(remote.failures)
                ),
                "scm_request_count": (
                    source.request_count
                ),
                "round_count": len(
                    result.rounds
                ),
                "usage": (
                    result.usage.as_dict()
                ),
                "estimated_cost_usd": (
                    round(
                        result
                        .estimated_cost_usd,
                        8,
                    )
                ),
                "status": "succeeded",
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 0


def add_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument(
        "--scm-snapshot",
        default=os.getenv(
            "SCM_INVENTORY_SNAPSHOT",
            "",
        ),
    )
    parser.add_argument(
        "--scm-provider",
        choices=[
            "github",
            "gitlab",
        ],
        default=os.getenv(
            "SCM_PROVIDER",
            "",
        ),
    )
    selector = (
        parser.add_mutually_exclusive_group()
    )
    selector.add_argument(
        "--repository-name",
        default=os.getenv(
            "SCM_REPOSITORY",
            "",
        ),
    )
    selector.add_argument(
        "--repository-external-id",
        default=os.getenv(
            "SCM_REPOSITORY_EXTERNAL_ID",
            "",
        ),
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
        "--max-remote-files",
        type=int,
        default=50,
    )
    parser.add_argument(
        "--max-remote-bytes",
        type=int,
        default=2 * 1024 * 1024,
    )
    parser.add_argument(
        "--allow-partial-evidence",
        action="store_true",
    )
    parser.add_argument(
        "--max-minutes",
        type=float,
        default=30,
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
    if (
        not args.repository_name
        and not args.repository_external_id
    ):
        raise ValueError(
            "Set --repository-name or "
            "--repository-external-id"
        )

    if args.max_remote_files < 1:
        raise ValueError(
            "--max-remote-files must be positive"
        )

    if args.max_remote_bytes < 1:
        raise ValueError(
            "--max-remote-bytes must be positive"
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

    args.output_root = getattr(
        args,
        "output_root",
        str(
            output_root() / "ai"
        ),
    )
