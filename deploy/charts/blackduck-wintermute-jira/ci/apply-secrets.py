#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


DNS_LABEL = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$"
)


def required(name: str) -> str:
    value = os.getenv(name, "")

    if not value.strip():
        raise RuntimeError(
            f"Required environment variable is empty: {name}"
        )

    if "\n" in value or "\r" in value:
        raise RuntimeError(
            f"{name} must not contain a newline"
        )

    return value


def valid_name(name: str, value: str) -> str:
    if (
        len(value) > 63
        or not DNS_LABEL.fullmatch(value)
    ):
        raise RuntimeError(
            f"{name} is not a valid Kubernetes name"
        )

    return value


def encoded(value: str) -> str:
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("ascii")


def main() -> int:
    namespace = valid_name(
        "KUBE_NAMESPACE",
        required("KUBE_NAMESPACE"),
    )
    registry_secret = valid_name(
        "WINTERMUTE_IMAGE_PULL_SECRET",
        required("WINTERMUTE_IMAGE_PULL_SECRET"),
    )
    runtime_secret = valid_name(
        "WINTERMUTE_RUNTIME_SECRET",
        required("WINTERMUTE_RUNTIME_SECRET"),
    )

    registry = required(
        "ARTIFACTORY_REGISTRY"
    )
    registry_username = required(
        "ARTIFACTORY_USERNAME"
    )
    registry_password = required(
        "ARTIFACTORY_PASSWORD"
    )

    if "://" in registry or "/" in registry:
        raise RuntimeError(
            "ARTIFACTORY_REGISTRY must contain only "
            "the registry hostname and optional port"
        )

    pair = (
        f"{registry_username}:"
        f"{registry_password}"
    )
    docker_configuration = json.dumps(
        {
            "auths": {
                registry: {
                    "username": registry_username,
                    "password": registry_password,
                    "auth": encoded(pair),
                }
            }
        },
        separators=(",", ":"),
    )

    runtime_values = {
        name: required(name)
        for name in (
            "BLACKDUCK_URL",
            "BLACKDUCK_API_TOKEN",
            "JIRA_URL",
            "JIRA_USER",
            "JIRA_API_TOKEN",
        )
    }

    items: list[dict[str, Any]] = [
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": registry_secret,
                "namespace": namespace,
            },
            "type": (
                "kubernetes.io/dockerconfigjson"
            ),
            "data": {
                ".dockerconfigjson": encoded(
                    docker_configuration
                ),
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": runtime_secret,
                "namespace": namespace,
            },
            "type": "Opaque",
            "data": {
                name: encoded(value)
                for name, value
                in runtime_values.items()
            },
        },
    ]

    ca_bundle_file = os.getenv(
        "CA_BUNDLE_FILE",
        "",
    ).strip()

    if ca_bundle_file:
        ca_path = Path(ca_bundle_file)

        if not ca_path.is_file():
            raise RuntimeError(
                "CA_BUNDLE_FILE does not exist: "
                f"{ca_path}"
            )

        ca_bundle = ca_path.read_text(
            encoding="utf-8"
        )

        if (
            "-----BEGIN CERTIFICATE-----"
            not in ca_bundle
        ):
            raise RuntimeError(
                "CA_BUNDLE_FILE does not contain "
                "a PEM certificate"
            )

        configmap_name = valid_name(
            "WINTERMUTE_CA_BUNDLE_CONFIGMAP",
            required(
                "WINTERMUTE_CA_BUNDLE_CONFIGMAP"
            ),
        )

        items.append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": configmap_name,
                    "namespace": namespace,
                },
                "data": {
                    "ca.crt": ca_bundle,
                },
            }
        )

    json.dump(
        {
            "apiVersion": "v1",
            "kind": "List",
            "items": items,
        },
        sys.stdout,
        separators=(",", ":"),
    )
    print()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        raise SystemExit(2)
