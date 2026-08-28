#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class MultiProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderRun:
    provider: str
    snapshot_id: str
    return_code: int
    elapsed_seconds: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "snapshot_id": self.snapshot_id,
            "return_code": self.return_code,
            "elapsed_seconds": (
                self.elapsed_seconds
            ),
        }


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def output_root(root: Path) -> Path:
    configured = os.getenv(
        "WINTERMUTE_OUTPUT_DIR",
        "",
    ).strip()

    if not configured:
        return root / ".wintermute"

    selected = Path(configured).expanduser()

    if selected.is_absolute():
        return selected

    return root / selected


def create_run_id() -> str:
    return (
        "scm-multi-"
        + time.strftime(
            "%Y%m%dT%H%M%SZ",
            time.gmtime(),
        )
        + "-"
        + uuid.uuid4().hex[:8]
    )


def atomic_write_json(
    path: Path,
    payload: Any,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    temporary = path.with_name(
        f"{path.name}.{uuid.uuid4().hex}.tmp"
    )

    try:
        temporary.write_text(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        os.replace(
            temporary,
            path,
        )
    finally:
        temporary.unlink(missing_ok=True)


def required_pair(
    environment: dict[str, str],
    first: str,
    second: str,
) -> bool:
    first_set = bool(
        environment.get(first, "").strip()
    )
    second_set = bool(
        environment.get(second, "").strip()
    )

    if first_set != second_set:
        raise MultiProviderError(
            f"{first} and {second} must either "
            "both be set or both be absent"
        )

    return first_set


def gitlab_url(
    environment: dict[str, str],
) -> str:
    return (
        environment.get(
            "GITLAB_URL",
            "",
        ).strip()
        or environment.get(
            "GITLAB_REST_URL",
            "",
        ).strip()
        or environment.get(
            "SCM_URL",
            "",
        ).strip()
    )


def configured_providers(
    environment: dict[str, str],
    args: argparse.Namespace,
) -> tuple[str, ...]:
    github = required_pair(
        environment,
        "GITHUB_ORG",
        "GITHUB_TOKEN",
    )
    gitlab = required_pair(
        environment,
        "GITLAB_GROUP",
        "GITLAB_TOKEN",
    )

    if gitlab and not gitlab_url(environment):
        raise MultiProviderError(
            "GitLab requires GITLAB_URL, "
            "GITLAB_REST_URL, or SCM_URL"
        )

    if args.github_only:
        if not github:
            raise MultiProviderError(
                "GitHub credentials are not configured"
            )

        return ("github",)

    if args.gitlab_only:
        if not gitlab:
            raise MultiProviderError(
                "GitLab credentials are not configured"
            )

        return ("gitlab",)

    providers = tuple(
        provider
        for provider, configured in (
            ("github", github),
            ("gitlab", gitlab),
        )
        if configured
    )

    if not providers:
        raise MultiProviderError(
            "No complete GitHub or GitLab "
            "configuration was found"
        )

    return providers


def base_arguments(
    args: argparse.Namespace,
    *,
    output: Path,
    snapshot_id: str,
) -> list[str]:
    arguments = [
        sys.executable,
        "-m",
        "wintermute.scm.overview",
        "--output-root",
        str(output),
        "--snapshot-id",
        snapshot_id,
        "--workers",
        str(args.workers),
        "--evidence-workers",
        str(args.evidence_workers),
        "--pipeline-limit",
        str(args.pipeline_limit),
        "--scan-evidence-workers",
        str(args.scan_evidence_workers),
        "--page-size",
        str(args.page_size),
        "--page-limit",
        str(args.page_limit),
        "--freshness-sla-days",
        str(args.freshness_sla_days),
        "--retain-snapshots",
        str(args.retain_snapshots),
        "--timeout",
        str(args.timeout),
        "--retries",
        str(args.retries),
        "--retry-delay",
        str(args.retry_delay),
        "--max-hours",
        str(args.max_hours),
    ]

    if args.collect_direct_scan_evidence:
        arguments.append(
            "--collect-direct-scan-evidence"
        )

    if args.allow_partial:
        arguments.append(
            "--allow-partial"
        )

    if args.max_projects is not None:
        arguments.extend(
            [
                "--max-projects",
                str(args.max_projects),
            ]
        )

    if args.max_versions is not None:
        arguments.extend(
            [
                "--max-versions",
                str(args.max_versions),
            ]
        )

    if args.insecure:
        arguments.append("--insecure")
    elif args.ca_bundle:
        arguments.extend(
            [
                "--ca-bundle",
                args.ca_bundle,
            ]
        )

    return arguments


def provider_environment(
    environment: dict[str, str],
    provider: str,
) -> dict[str, str]:
    selected = dict(environment)

    if provider == "github":
        for name in (
            "SCM_URL",
            "SCM_PROVIDER",
            "GITLAB_URL",
            "GITLAB_GROUP",
            "GITLAB_REST_URL",
            "GITLAB_TOKEN",
        ):
            selected.pop(name, None)
    else:
        for name in (
            "GITHUB_ORG",
            "GITHUB_TOKEN",
            "GITHUB_GRAPHQL_URL",
            "GITHUB_REST_URL",
        ):
            selected.pop(name, None)

        selected["SCM_URL"] = (
            gitlab_url(environment)
        )

    return selected


def provider_arguments(
    provider: str,
    environment: dict[str, str],
) -> list[str]:
    if provider == "github":
        return [
            "--organization",
            environment["GITHUB_ORG"],
        ]

    return [
        "--scm-url",
        gitlab_url(environment),
        "--group",
        environment["GITLAB_GROUP"],
    ]


def run_provider(
    provider: str,
    args: argparse.Namespace,
    *,
    root: Path,
    output: Path,
    environment: dict[str, str],
    run_id: str,
) -> ProviderRun:
    snapshot_id = (
        f"{run_id}-{provider}"
    )
    command = [
        *base_arguments(
            args,
            output=output,
            snapshot_id=snapshot_id,
        ),
        *provider_arguments(
            provider,
            environment,
        ),
    ]
    started = time.monotonic()

    print()
    print("=" * 72)
    print(
        f"SCM provider run: {provider}"
    )
    print("=" * 72)
    sys.stdout.flush()

    try:
        completed = subprocess.run(
            command,
            cwd=str(root),
            env=provider_environment(
                environment,
                provider,
            ),
            stdin=subprocess.DEVNULL,
            timeout=args.provider_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise MultiProviderError(
            f"{provider} exceeded "
            f"{args.provider_timeout:g} seconds"
        ) from error

    return ProviderRun(
        provider=provider,
        snapshot_id=snapshot_id,
        return_code=completed.returncode,
        elapsed_seconds=round(
            time.monotonic() - started,
            3,
        ),
    )


def run(args: argparse.Namespace) -> int:
    root = project_root()
    output = output_root(root)
    environment = dict(os.environ)
    environment[
        "WINTERMUTE_OUTPUT_DIR"
    ] = str(output)
    environment["PYTHONUNBUFFERED"] = "1"

    for name in (
        "BLACKDUCK_URL",
        "BLACKDUCK_API_TOKEN",
    ):
        if not environment.get(
            name,
            "",
        ).strip():
            raise MultiProviderError(
                f"{name} must be set"
            )

    providers = configured_providers(
        environment,
        args,
    )
    run_id = (
        args.run_id or create_run_id()
    )
    results: list[ProviderRun] = []

    for provider in providers:
        results.append(
            run_provider(
                provider,
                args,
                root=root,
                output=output,
                environment=environment,
                run_id=run_id,
            )
        )

    failed = [
        result
        for result in results
        if result.return_code != 0
    ]
    summary = {
        "schema_version": 1,
        "run_id": run_id,
        "status": (
            "succeeded"
            if not failed
            else "partial"
            if len(failed) < len(results)
            else "failed"
        ),
        "provider_count": len(results),
        "providers": [
            result.as_dict()
            for result in results
        ],
    }
    summary_path = (
        output
        / "scm"
        / "multi-provider"
        / run_id
        / "summary.json"
    )
    atomic_write_json(
        summary_path,
        summary,
    )
    print()
    print(
        json.dumps(
            {
                **summary,
                "summary_path": (
                    str(summary_path)
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 1 if failed else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run sequential GitHub and GitLab "
            "inventory and Black Duck coverage."
        )
    )
    selected = parser.add_mutually_exclusive_group()
    selected.add_argument(
        "--github-only",
        action="store_true",
    )
    selected.add_argument(
        "--gitlab-only",
        action="store_true",
    )
    parser.add_argument("--run-id")
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--evidence-workers",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--pipeline-limit",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--scan-evidence-workers",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--page-limit",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--freshness-sla-days",
        type=int,
        default=30,
    )
    parser.add_argument(
        "--retain-snapshots",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--max-projects",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--max-versions",
        type=int,
        default=5,
    )
    parser.add_argument(
        "--collect-direct-scan-evidence",
        action="store_true",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
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
    parser.add_argument(
        "--provider-timeout",
        type=float,
        default=7200,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument(
        "--ca-bundle",
    )
    args = parser.parse_args()

    for name in (
        "workers",
        "evidence_workers",
        "pipeline_limit",
        "scan_evidence_workers",
        "page_size",
        "page_limit",
        "freshness_sla_days",
        "retain_snapshots",
        "timeout",
    ):
        if int(getattr(args, name)) < 1:
            parser.error(
                f"--{name.replace('_', '-')} "
                "must be positive"
            )

    if args.retries < 0:
        parser.error(
            "--retries cannot be negative"
        )

    if args.retry_delay < 0:
        parser.error(
            "--retry-delay cannot be negative"
        )

    if args.max_hours <= 0:
        parser.error(
            "--max-hours must be positive"
        )

    if args.provider_timeout <= 0:
        parser.error(
            "--provider-timeout must be positive"
        )

    return args


def main() -> int:
    try:
        return run(parse_args())
    except KeyboardInterrupt:
        return 130
    except (
        MultiProviderError,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
