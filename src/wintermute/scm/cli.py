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
    DEFAULT_REST_BASE_URL,
    GitHubRestClient,
    GitHubRestError,
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


def validate_args(
    args: argparse.Namespace,
) -> None:
    if not str(
        args.organization or ""
    ).strip():
        raise RuntimeError(
            "GitHub organization must be supplied "
            "with --organization or GITHUB_ORG"
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

    if not 1 <= args.evidence_workers <= 8:
        raise RuntimeError(
            "--evidence-workers must be between 1 and 8"
        )


def run(
    args: argparse.Namespace,
) -> int:
    validate_args(args)
    token = os.getenv(
        "GITHUB_TOKEN",
        "",
    ).strip()

    if not token:
        raise RuntimeError(
            "GITHUB_TOKEN must be set"
        )

    deadline = (
        time.monotonic()
        + args.max_hours * 3600
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
            "GitHub inventory expected exactly one tenant"
        )

    tenant = tenants[0]
    inventory = client.inventory(tenant)
    observations = (
        empty_observations()
    )
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
                "refer to different provider instances"
            )

        observation_provider = (
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
            )
        )
        observations = (
            observation_provider.observe(
                tenant,
                inventory,
            )
        )
        rest_stats = rest_client.stats()

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

    graphql_stats = client.stats()
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
        "rest_requests": (
            rest_stats.requests
            if rest_stats is not None
            else 0
        ),
        "rest_retries": (
            rest_stats.retries
            if rest_stats is not None
            else 0
        ),
        "rest_rate_remaining": (
            rest_stats.rate_remaining
            if rest_stats is not None
            else None
        ),
        "provider_evidence_skipped": (
            args.skip_provider_evidence
        ),
        "status": (
            "partial"
            if failure_count
            else "succeeded"
        ),
    }
    print(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
    )

    return (
        1
        if failure_count
        else 0
    )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create an immutable, provider-neutral "
            "Wintermute SCM repository and evidence snapshot."
        )
    )
    parser.add_argument(
        "--organization",
        default=os.getenv("GITHUB_ORG"),
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
            DEFAULT_REST_BASE_URL,
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
        help=(
            "Skip read-only custom-property and "
            "ruleset evidence collection."
        ),
    )
    parser.add_argument(
        "--evidence-workers",
        type=int,
        default=4,
        help=(
            "Concurrent read-only repository workflow "
            "inventory requests. Range: 1-8."
        ),
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
        default=30.0,
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=1.0,
    )
    parser.add_argument(
        "--max-hours",
        type=float,
        default=2.0,
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
    token = os.getenv(
        "GITHUB_TOKEN",
        "",
    )

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
        SnapshotError,
        RuntimeError,
        ValueError,
    ) as error:
        message = str(error)

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
