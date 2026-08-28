from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from wintermute.paths import (
    ensure_parent_dir,
    output_root,
)
from wintermute.scm.controls import (
    ControlInventory,
)
from wintermute.scm.evidence import (
    EvidenceInventory,
)
from wintermute.scm.observations import (
    ScmObservationResult,
)
from wintermute.scm.providers.detection import (
    gitlab_group_from_url,
    gitlab_rest_url,
    select_provider,
)
from wintermute.scm.providers.github.client import (
    DEFAULT_GRAPHQL_ENDPOINT,
    GitHubClient,
    GitHubClientError,
)
from wintermute.scm.providers.github.controls import (
    GitHubControlSettings,
)
from wintermute.scm.providers.github.mapper import (
    GitHubMappingError,
)
from wintermute.scm.providers.github.observations import (
    GitHubObservationProvider,
)
from wintermute.scm.providers.github.rest import (
    DEFAULT_REST_BASE_URL as DEFAULT_GITHUB_REST_URL,
    GitHubRestClient,
    GitHubRestError,
)
from wintermute.scm.providers.gitlab.client import (
    DEFAULT_REST_BASE_URL as DEFAULT_GITLAB_REST_URL,
    GitLabRestError,
)
from wintermute.scm.providers.gitlab.inventory import (
    GitLabClient,
)
from wintermute.scm.providers.gitlab.observations import (
    GitLabObservationProvider,
)
from wintermute.scm.snapshots import (
    SnapshotError,
    write_inventory_snapshot,
)


def default_snapshot_root() -> str:
    return str(
        output_root()
        / "scm"
        / "inventory"
        / "snapshots"
    )


def atomic_write_text(
    path: str,
    value: str,
) -> None:
    ensure_parent_dir(path)
    destination = Path(path)
    temporary = destination.with_name(
        f"{destination.name}.tmp"
    )
    temporary.write_text(
        value,
        encoding="utf-8",
    )
    os.replace(
        temporary,
        destination,
    )


def empty_observations() -> ScmObservationResult:
    return ScmObservationResult(
        evidence=EvidenceInventory(
            observations=()
        ),
        controls=ControlInventory(
            observations=()
        ),
    )


def provider_name(
    args: argparse.Namespace,
) -> str:
    return select_provider(
        args.scm_url,
        gitlab_group=args.group or "",
        gitlab_rest_base_url=(
            args.gitlab_rest_url or ""
        ),
        github_graphql_url=(
            args.graphql_endpoint
        ),
    ).provider


def validate_args(
    args: argparse.Namespace,
) -> None:
    provider = provider_name(args)

    if provider == "github":
        if not str(
            args.organization or ""
        ).strip():
            raise RuntimeError(
                "GitHub organization must be supplied "
                "with --organization or GITHUB_ORG"
            )
    elif not str(
        args.group or ""
    ).strip():
        derived = gitlab_group_from_url(
            args.scm_url
        )

        if not derived:
            raise RuntimeError(
                "GitLab group must be supplied with "
                "--group or GITLAB_GROUP"
            )

    if args.timeout <= 0:
        raise RuntimeError(
            "--timeout must be greater than zero"
        )

    if args.retries < 0:
        raise RuntimeError(
            "--retries cannot be negative"
        )

    if args.retry_delay < 0:
        raise RuntimeError(
            "--retry-delay cannot be negative"
        )

    if not 1 <= args.page_size <= 100:
        raise RuntimeError(
            "--page-size must be between 1 and 100"
        )

    if args.activity_days < 1:
        raise RuntimeError(
            "--activity-days must be greater than zero"
        )

    if args.max_hours <= 0:
        raise RuntimeError(
            "--max-hours must be greater than zero"
        )

    if not 1 <= args.workers <= 8:
        raise RuntimeError(
            "--workers must be between 1 and 8"
        )

    if not 1 <= args.evidence_workers <= 8:
        raise RuntimeError(
            "--evidence-workers must be between 1 and 8"
        )

    if not 1 <= args.pipeline_limit <= 100:
        raise RuntimeError(
            "--pipeline-limit must be between 1 and 100"
        )


def github_run(
    args: argparse.Namespace,
    deadline: float,
) -> tuple[
    Any,
    Any,
    Any,
    Any,
]:
    token = os.getenv(
        "GITHUB_TOKEN",
        "",
    ).strip()

    if not token:
        raise RuntimeError(
            "GITHUB_TOKEN must be set"
        )

    client = GitHubClient(
        organization=args.organization,
        token=token,
        endpoint=args.graphql_endpoint,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_size=args.page_size,
        activity_days=args.activity_days,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        deadline=deadline,
    )
    tenants = client.list_tenants()

    if len(tenants) != 1:
        raise RuntimeError(
            "GitHub inventory expected exactly "
            "one tenant"
        )

    tenant = tenants[0]
    inventory = client.inventory(tenant)
    observations = empty_observations()
    rest_stats = None

    if not args.skip_provider_evidence:
        rest_client = GitHubRestClient(
            token,
            base_url=args.rest_base_url,
            timeout=args.timeout,
            retries=args.retries,
            retry_delay=args.retry_delay,
            insecure=args.insecure,
            ca_bundle=args.ca_bundle,
            deadline=deadline,
        )

        if (
            rest_client.provider_instance
            != tenant.provider_instance
        ):
            raise RuntimeError(
                "GitHub GraphQL and REST endpoints "
                "refer to different instances"
            )

        observations = (
            GitHubObservationProvider(
                rest_client,
                control_settings=(
                    GitHubControlSettings(
                        property_name=(
                            args.property_name
                        ),
                        onboarding_values=tuple(
                            args.onboarding_value
                            or ["required"]
                        ),
                        ruleset_name=(
                            args.ruleset_name
                        ),
                    )
                ),
                workers=args.evidence_workers,
            ).observe(
                tenant,
                inventory,
            )
        )
        rest_stats = rest_client.stats()

    return (
        tenant,
        inventory,
        observations,
        {
            "graphql": client.stats(),
            "rest": rest_stats,
        },
    )


def gitlab_run(
    args: argparse.Namespace,
    deadline: float,
) -> tuple[
    Any,
    Any,
    Any,
    Any,
]:
    token = os.getenv(
        "GITLAB_TOKEN",
        "",
    ).strip()

    if not token:
        raise RuntimeError(
            "GITLAB_TOKEN must be set"
        )

    group = str(
        args.group
        or gitlab_group_from_url(
            args.scm_url
        )
        or ""
    ).strip()
    source_url = (
        args.scm_url
        or args.gitlab_rest_url
        or DEFAULT_GITLAB_REST_URL
    )
    client = GitLabClient(
        group=group,
        token=token,
        base_url=gitlab_rest_url(
            source_url
        ),
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_size=args.page_size,
        activity_days=args.activity_days,
        workers=args.workers,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        deadline=deadline,
    )
    tenants = client.list_tenants()

    if len(tenants) != 1:
        raise RuntimeError(
            "GitLab inventory expected exactly "
            "one tenant"
        )

    tenant = tenants[0]
    inventory = client.inventory(tenant)
    observations = empty_observations()

    if not args.skip_provider_evidence:
        observations = (
            GitLabObservationProvider(
                client,
                workers=args.evidence_workers,
                pipeline_limit=(
                    args.pipeline_limit
                ),
            ).observe(
                tenant,
                inventory,
            )
        )

    return (
        tenant,
        inventory,
        observations,
        {
            "graphql": client.graphql_stats(),
            "rest": client.stats(),
        },
    )


def run(
    args: argparse.Namespace,
) -> int:
    validate_args(args)
    deadline = (
        time.monotonic()
        + args.max_hours * 3600
    )
    provider = provider_name(args)

    if provider == "gitlab":
        (
            tenant,
            inventory,
            observations,
            stats,
        ) = gitlab_run(
            args,
            deadline,
        )
    else:
        (
            tenant,
            inventory,
            observations,
            stats,
        ) = github_run(
            args,
            deadline,
        )

    snapshot_directory = (
        write_inventory_snapshot(
            args.snapshot_root,
            tenant,
            inventory,
            observations=observations,
            snapshot_id=args.snapshot_id,
        )
    )

    if args.snapshot_id_out:
        atomic_write_text(
            args.snapshot_id_out,
            snapshot_directory.name + "\n",
        )

    failure_count = (
        inventory.failure_count
        + observations.failure_count
    )
    summary: dict[str, Any] = {
        "snapshot_id": (
            snapshot_directory.name
        ),
        "snapshot_directory": str(
            snapshot_directory
        ),
        "provider": tenant.provider,
        "provider_instance": (
            tenant.provider_instance
        ),
        "tenant_id": tenant.tenant_id,
        "namespace": tenant.namespace,
        "discovered_repository_count": (
            inventory.discovered_count
        ),
        "repository_count": (
            inventory.repository_count
        ),
        "exclusion_count": (
            inventory.exclusion_count
        ),
        "inventory_failure_count": (
            inventory.failure_count
        ),
        "evidence_observation_count": (
            observations
            .evidence
            .observation_count
        ),
        "evidence_failure_count": (
            observations
            .evidence
            .failure_count
        ),
        "control_observation_count": (
            observations
            .controls
            .observation_count
        ),
        "control_failure_count": (
            observations
            .controls
            .failure_count
        ),
        "observation_failure_count": (
            observations.failure_count
        ),
        "failure_count": failure_count,
        "reconciled": inventory.reconciled,
        "graphql_requests": 0,
        "graphql_retries": 0,
        "graphql_cost": 0,
        "graphql_rate_remaining": None,
        "rest_requests": 0,
        "rest_retries": 0,
        "rest_rate_remaining": None,
        "provider_evidence_skipped": (
            args.skip_provider_evidence
        ),
        "status": (
            "partial"
            if failure_count
            else "succeeded"
        ),
    }

    graphql_stats = stats.get("graphql")
    rest_stats = stats.get("rest")

    if graphql_stats is not None:
        summary.update(
            {
                "graphql_requests": (
                    graphql_stats.requests
                ),
                "graphql_retries": (
                    graphql_stats.retries
                ),
                "graphql_cost": (
                    graphql_stats.graphql_cost
                ),
                "graphql_rate_remaining": (
                    graphql_stats.rate_remaining
                ),
            }
        )

    if rest_stats is not None:
        summary.update(
            {
                "rest_requests": (
                    rest_stats.requests
                ),
                "rest_retries": (
                    rest_stats.retries
                ),
                "rest_rate_remaining": (
                    rest_stats.rate_remaining
                ),
            }
        )

    print(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
    )

    return 1 if failure_count else 0


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create an immutable, provider-neutral "
            "SCM repository and evidence snapshot."
        )
    )
    parser.add_argument(
        "--scm-url",
        default=os.getenv(
            "SCM_URL",
            "",
        ),
    )
    parser.add_argument(
        "--organization",
        default=os.getenv("GITHUB_ORG"),
    )
    parser.add_argument(
        "--group",
        default=os.getenv("GITLAB_GROUP"),
    )
    parser.add_argument(
        "--graphql-endpoint",
        default=os.getenv(
            "GITHUB_GRAPHQL_URL",
            DEFAULT_GRAPHQL_ENDPOINT,
        ),
    )
    parser.add_argument(
        "--rest-base-url",
        default=os.getenv(
            "GITHUB_REST_URL",
            DEFAULT_GITHUB_REST_URL,
        ),
    )
    parser.add_argument(
        "--gitlab-rest-url",
        default=os.getenv(
            "GITLAB_REST_URL",
            "",
        ),
    )
    parser.add_argument(
        "--snapshot-root",
        default=default_snapshot_root(),
    )
    parser.add_argument("--snapshot-id")
    parser.add_argument("--snapshot-id-out")
    parser.add_argument(
        "--property-name",
        default="blackduck_sca_policy",
    )
    parser.add_argument(
        "--onboarding-value",
        action="append",
        default=None,
    )
    parser.add_argument(
        "--ruleset-name",
        default="",
    )
    parser.add_argument(
        "--skip-provider-evidence",
        action="store_true",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--evidence-workers",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--pipeline-limit",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--activity-days",
        type=int,
        default=180,
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=1,
    )
    parser.add_argument(
        "--max-hours",
        type=float,
        default=2,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument("--ca-bundle")

    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
) -> int:
    tokens = [
        os.getenv("GITHUB_TOKEN", ""),
        os.getenv("GITLAB_TOKEN", ""),
    ]

    try:
        return run(
            parse_args(argv)
        )
    except KeyboardInterrupt:
        print(
            "Interrupted.",
            file=sys.stderr,
        )
        return 130
    except (
        GitHubClientError,
        GitHubMappingError,
        GitHubRestError,
        GitLabRestError,
        SnapshotError,
        RuntimeError,
        ValueError,
    ) as error:
        message = str(error)

        for token in tokens:
            if token:
                message = message.replace(
                    token,
                    "[REDACTED]",
                )

        print(
            f"ERROR: {message}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
