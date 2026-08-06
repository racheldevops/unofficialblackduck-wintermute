#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


REQUIRED_CRDS = (
    "workflowtemplates.argoproj.io",
    "cronworkflows.argoproj.io",
    "workflows.argoproj.io",
)

REQUIRED_SECRETS = (
    "blackduck-wintermute-registry",
    "blackduck-wintermute-blackduck-credentials",
    "blackduck-wintermute-jira-credentials",
    "blackduck-wintermute-datadog-credentials",
)

APPLY_RESOURCES = (
    "workflowtemplates.argoproj.io",
    "cronworkflows.argoproj.io",
    "persistentvolumeclaims",
    "configmaps",
    "serviceaccounts",
    "roles.rbac.authorization.k8s.io",
    "rolebindings.rbac.authorization.k8s.io",
)

SECRET_RE = re.compile(
    r"(?im)"
    r"(?P<key>[A-Za-z0-9_.-]*"
    r"(?:token|password|secret|api[_-]?key|authorization))"
    r"(?P<separator>[ \t]*[=:][ \t]*)"
    r"(?P<value>"
    r"(?!false\b|true\b|null\b|~\b)"
    r"[^\s]+)"
)


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str = ""


def redact(value: str) -> str:
    return SECRET_RE.sub(
        r"\g<key>\g<separator><redacted>",
        str(value or ""),
    )


def run_kubectl(
    kubectl: str,
    arguments: list[str],
    *,
    timeout: int = 120,
) -> tuple[int, str]:
    completed = subprocess.run(
        [kubectl, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )

    return (
        completed.returncode,
        redact(completed.stdout or "").strip(),
    )


def validate_rendered_manifest(
    manifest: str,
    namespace: str,
) -> list[str]:
    errors: list[str] = []

    for placeholder in (
        "registry.invalid",
        ":replace-me",
        "REPLACE_ME",
    ):
        if placeholder in manifest:
            errors.append(
                f"Rendered manifest contains placeholder: {placeholder}"
            )

    for kind in (
        "WorkflowTemplate",
        "CronWorkflow",
    ):
        if f"kind: {kind}" not in manifest:
            errors.append(
                f"Rendered manifest is missing {kind}"
            )

    if f"namespace: {namespace}" not in manifest:
        errors.append(
            f"Rendered manifest does not target namespace {namespace}"
        )

    expected_images = {
        "source": 2,
        "jira": 1,
        "datadog": 1,
    }

    for target, expected_count in expected_images.items():
        pattern = re.compile(
            rf"(?m)^\s*image:\s*\S*"
            rf"blackduck-wintermute-{target}:"
            rf"[A-Za-z0-9_.-]+\s*$"
        )
        actual_count = len(pattern.findall(manifest))

        if actual_count != expected_count:
            errors.append(
                f"Expected {expected_count} {target} image reference(s), "
                f"found {actual_count}"
            )

    if re.search(
        r"(?m)^kind:\s*Secret\s*$",
        manifest,
    ):
        errors.append(
            "Rendered deployment manifest must not contain Secrets"
        )

    if "suspend: true" not in manifest:
        errors.append(
            "Rendered CronWorkflow is not suspended"
        )

    return errors


def validate_cluster(
    manifest_path: Path,
    namespace: str,
    *,
    kubectl: str,
    require_secrets: bool,
) -> dict[str, Any]:
    checks: list[Check] = []

    if not manifest_path.is_file():
        return {
            "ok": False,
            "namespace": namespace,
            "checks": [
                asdict(
                    Check(
                        name="manifest-exists",
                        ok=False,
                        detail=f"Missing manifest: {manifest_path}",
                    )
                )
            ],
        }

    manifest = manifest_path.read_text(
        encoding="utf-8"
    )
    manifest_errors = validate_rendered_manifest(
        manifest,
        namespace,
    )
    checks.append(
        Check(
            name="manifest-policy",
            ok=not manifest_errors,
            detail="; ".join(manifest_errors),
        )
    )

    return_code, output = run_kubectl(
        kubectl,
        ["config", "current-context"],
    )
    checks.append(
        Check(
            name="kubernetes-context",
            ok=return_code == 0,
            detail=output,
        )
    )

    for crd in REQUIRED_CRDS:
        return_code, output = run_kubectl(
            kubectl,
            ["get", "crd", crd, "-o", "name"],
        )
        checks.append(
            Check(
                name=f"crd:{crd}",
                ok=return_code == 0,
                detail=output,
            )
        )

    return_code, output = run_kubectl(
        kubectl,
        [
            "get",
            "namespace",
            namespace,
            "-o",
            "name",
        ],
    )
    namespace_exists = return_code == 0
    checks.append(
        Check(
            name="namespace",
            ok=namespace_exists,
            detail=output,
        )
    )

    if require_secrets and namespace_exists:
        for secret in REQUIRED_SECRETS:
            return_code, output = run_kubectl(
                kubectl,
                [
                    "get",
                    "secret",
                    secret,
                    "--namespace",
                    namespace,
                    "-o",
                    "name",
                ],
            )
            checks.append(
                Check(
                    name=f"secret:{secret}",
                    ok=return_code == 0,
                    detail=output,
                )
            )

    if namespace_exists:
        for resource in APPLY_RESOURCES:
            for verb in ("create", "patch"):
                return_code, output = run_kubectl(
                    kubectl,
                    [
                        "auth",
                        "can-i",
                        verb,
                        resource,
                        "--namespace",
                        namespace,
                    ],
                )
                allowed = (
                    return_code == 0
                    and output.strip().lower() == "yes"
                )
                checks.append(
                    Check(
                        name=f"rbac:{verb}:{resource}",
                        ok=allowed,
                        detail=output,
                    )
                )

        return_code, output = run_kubectl(
            kubectl,
            [
                "apply",
                "--server-side",
                "--dry-run=server",
                "--field-manager",
                "blackduck-wintermute-cohort-preflight",
                "--filename",
                str(manifest_path),
            ],
            timeout=300,
        )
        checks.append(
            Check(
                name="server-dry-run",
                ok=return_code == 0,
                detail=output,
            )
        )

    return {
        "ok": all(check.ok for check in checks),
        "namespace": namespace,
        "manifest": str(manifest_path),
        "checks": [
            asdict(check)
            for check in checks
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate Wintermute cohort cluster prerequisites "
            "without reading Secret contents."
        )
    )
    parser.add_argument(
        "--manifest",
        required=True,
    )
    parser.add_argument(
        "--namespace",
        required=True,
    )
    parser.add_argument(
        "--kubectl",
        default="kubectl",
    )
    parser.add_argument(
        "--require-secrets",
        action="store_true",
    )
    parser.add_argument(
        "--report",
        default=(
            ".validation-results/"
            "cohort-cluster-preflight.json"
        ),
    )
    args = parser.parse_args()

    kubectl = shutil.which(args.kubectl)

    if not kubectl:
        print(
            f"ERROR: kubectl was not found: {args.kubectl}",
            file=sys.stderr,
        )
        return 2

    try:
        result = validate_cluster(
            Path(args.manifest),
            args.namespace,
            kubectl=kubectl,
            require_secrets=args.require_secrets,
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        print(
            f"ERROR: {redact(str(error))}",
            file=sys.stderr,
        )
        return 2

    report_path = Path(args.report)
    report_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    report_path.write_text(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    for check in result["checks"]:
        print(
            f"{'PASS' if check['ok'] else 'FAIL'} "
            f"{check['name']}"
        )

    print(f"Report: {report_path}")

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
