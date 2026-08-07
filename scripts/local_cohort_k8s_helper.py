#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
from typing import Any


VALID_MODES = {
    "disabled",
    "dry-run",
    "apply",
}


def encoded(value: str) -> str:
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("ascii")


def kubectl(
    arguments: list[str],
    *,
    payload: dict[str, Any] | None = None,
    allow_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["kubectl", *arguments],
        input=(
            json.dumps(payload)
            if payload is not None
            else None
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if (
        completed.returncode != 0
        and not allow_failure
    ):
        raise RuntimeError(
            completed.stderr.strip()
            or completed.stdout.strip()
            or "kubectl failed"
        )

    return completed


def secret_exists(
    namespace: str,
    name: str,
) -> bool:
    return kubectl(
        [
            "get",
            "secret",
            name,
            "--namespace",
            namespace,
            "--output",
            "name",
        ],
        allow_failure=True,
    ).returncode == 0


def secret_data(
    namespace: str,
    name: str,
) -> dict[str, str]:
    completed = kubectl(
        [
            "get",
            "secret",
            name,
            "--namespace",
            namespace,
            "--output",
            "json",
        ],
    )
    payload = json.loads(completed.stdout)
    data = payload.get("data", {})

    return (
        {
            str(key): str(value or "")
            for key, value in data.items()
        }
        if isinstance(data, dict)
        else {}
    )


def apply_payload(
    payload: dict[str, Any],
) -> None:
    completed = kubectl(
        [
            "apply",
            "--filename",
            "-",
        ],
        payload=payload,
    )

    if completed.stdout:
        print(completed.stdout, end="")


def apply_secrets(args: argparse.Namespace) -> int:
    blackduck_url = os.getenv(
        "BLACKDUCK_URL",
        "",
    )
    blackduck_token = os.getenv(
        "BLACKDUCK_API_TOKEN",
        "",
    )

    if not blackduck_url or not blackduck_token:
        raise RuntimeError(
            "Black Duck credentials are missing"
        )

    apply_payload(
        {
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": (
                            "blackduck-wintermute-"
                            "blackduck-credentials"
                        ),
                        "namespace": args.namespace,
                    },
                    "type": "Opaque",
                    "data": {
                        "BLACKDUCK_URL": encoded(
                            blackduck_url
                        ),
                        "BLACKDUCK_API_TOKEN": (
                            encoded(blackduck_token)
                        ),
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": (
                            "blackduck-wintermute-"
                            "registry"
                        ),
                        "namespace": args.namespace,
                    },
                    "type": (
                        "kubernetes.io/"
                        "dockerconfigjson"
                    ),
                    "data": {
                        ".dockerconfigjson": encoded(
                            '{"auths":{}}'
                        ),
                    },
                },
            ],
        }
    )

    for name in (
        "blackduck-wintermute-jira-credentials",
        "blackduck-wintermute-datadog-credentials",
    ):
        if secret_exists(
            args.namespace,
            name,
        ):
            continue

        apply_payload(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": name,
                    "namespace": args.namespace,
                },
                "type": "Opaque",
                "data": {},
            }
        )

    return 0


def validate_apply_credentials(
    args: argparse.Namespace,
) -> None:
    if args.jira_mode == "apply":
        data = secret_data(
            args.namespace,
            (
                "blackduck-wintermute-"
                "jira-credentials"
            ),
        )
        basic = all(
            data.get(name)
            for name in (
                "JIRA_URL",
                "JIRA_USER",
                "JIRA_API_TOKEN",
            )
        )
        bearer = all(
            data.get(name)
            for name in (
                "JIRA_URL",
                "JIRA_PAT",
            )
        )

        if not basic and not bearer:
            raise RuntimeError(
                "Jira apply credentials are not configured"
            )

    if args.datadog_mode == "apply":
        data = secret_data(
            args.namespace,
            (
                "blackduck-wintermute-"
                "datadog-credentials"
            ),
        )

        if not data.get("DATADOG_API_KEY"):
            raise RuntimeError(
                "Datadog apply credentials are not configured"
            )


def submit_workflow(
    args: argparse.Namespace,
) -> int:
    if args.jira_mode not in VALID_MODES:
        raise RuntimeError(
            f"Invalid Jira mode: {args.jira_mode}"
        )

    if args.datadog_mode not in VALID_MODES:
        raise RuntimeError(
            f"Invalid Datadog mode: {args.datadog_mode}"
        )

    if (
        "apply"
        in {
            args.jira_mode,
            args.datadog_mode,
        }
        and not args.confirm_apply
    ):
        raise RuntimeError(
            "Apply mode requires --confirm-apply"
        )

    if args.jira_max_create < 1:
        raise RuntimeError(
            "jira-max-create must be greater than zero"
        )

    if args.datadog_max_send < 1:
        raise RuntimeError(
            "datadog-max-send must be greater than zero"
        )

    validate_apply_credentials(args)

    parameters = [
        {
            "name": "source-image",
            "value": args.source_image,
        },
        {
            "name": "jira-image",
            "value": args.jira_image,
        },
        {
            "name": "datadog-image",
            "value": args.datadog_image,
        },
        {
            "name": "jira-mode",
            "value": args.jira_mode,
        },
        {
            "name": "datadog-mode",
            "value": args.datadog_mode,
        },
        {
            "name": "confirm-apply",
            "value": str(
                args.confirm_apply
            ).lower(),
        },
        {
            "name": "retain-cohorts",
            "value": str(args.retain_cohorts),
        },
        {
            "name": "jira-only-vulnerability",
            "value": (
                args.jira_only_vulnerability
            ),
        },
        {
            "name": "jira-max-create",
            "value": str(
                args.jira_max_create
            ),
        },
        {
            "name": "datadog-max-send",
            "value": str(
                args.datadog_max_send
            ),
        },
    ]
    manifest = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Workflow",
        "metadata": {
            "generateName": (
                "blackduck-wintermute-local-"
            ),
            "namespace": args.namespace,
            "labels": {
                "app.kubernetes.io/name": (
                    "blackduck-wintermute"
                ),
                "app.kubernetes.io/component": (
                    "local-cohort"
                ),
            },
        },
        "spec": {
            "workflowTemplateRef": {
                "name": (
                    "blackduck-wintermute-cohort"
                ),
            },
            "arguments": {
                "parameters": parameters,
            },
        },
    }
    completed = kubectl(
        [
            "create",
            "--filename",
            "-",
            "--output",
            "name",
        ],
        payload=manifest,
    )

    print(completed.stdout.strip())
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    apply_parser = commands.add_parser(
        "apply-secrets"
    )
    apply_parser.add_argument(
        "--namespace",
        required=True,
    )

    submit = commands.add_parser("submit")
    submit.add_argument(
        "--namespace",
        required=True,
    )
    submit.add_argument(
        "--source-image",
        required=True,
    )
    submit.add_argument(
        "--jira-image",
        required=True,
    )
    submit.add_argument(
        "--datadog-image",
        required=True,
    )
    submit.add_argument(
        "--jira-mode",
        choices=sorted(VALID_MODES),
        default="dry-run",
    )
    submit.add_argument(
        "--datadog-mode",
        choices=sorted(VALID_MODES),
        default="dry-run",
    )
    submit.add_argument(
        "--confirm-apply",
        action="store_true",
    )
    submit.add_argument(
        "--jira-only-vulnerability",
        default="",
    )
    submit.add_argument(
        "--jira-max-create",
        type=int,
        default=5000,
    )
    submit.add_argument(
        "--datadog-max-send",
        type=int,
        default=100,
    )
    submit.add_argument(
        "--retain-cohorts",
        type=int,
        default=3,
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        if args.command == "apply-secrets":
            return apply_secrets(args)

        return submit_workflow(args)
    except (
        RuntimeError,
        OSError,
        json.JSONDecodeError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
