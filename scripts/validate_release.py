#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


SECRET_RE = re.compile(
    r"(?im)"
    r"(?P<key>[A-Za-z0-9_.-]*"
    r"(?:token|password|secret|api[_-]?key|authorization))"
    r"(?P<separator>[ \t]*[=:][ \t]*)"
    r"(?P<value>"
    r"(?!false\b|true\b|null\b|~\b)"
    r"[^\s]+)"
)

def redact(value: str) -> str:
    return SECRET_RE.sub(
        r"\g<key>\g<separator><redacted>",
        value,
    )


def run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout: int = 300,
) -> tuple[int, str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )

    return (
        completed.returncode,
        redact(completed.stdout or ""),
    )


def entrypoint_names(
    project_root: Path,
) -> list[str]:
    payload = tomllib.loads(
        (project_root / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )

    return sorted(
        payload.get("project", {})
        .get("scripts", {})
    )


def validate_manifest(
    manifest: str,
) -> list[str]:
    errors: list[str] = []

    for flag in (
        "--workers",
        "--parent-workers",
        "--rollup-workers",
    ):
        pattern = (
            rf"- {re.escape(flag)}\s+"
            rf"- [\"']?8[\"']?"
        )

        if not re.search(
            pattern,
            manifest,
            re.MULTILINE,
        ):
            errors.append(
                f"Missing {flag} 8"
            )

    required_values = (
        "blackduck-wintermute-data",
        "/var/lib/blackduck-wintermute",
        "--resolve-bom-names",
        "readOnlyRootFilesystem: true",
        "allowPrivilegeEscalation: false",
        "automountServiceAccountToken: false",
        "runAsNonRoot: true",
        "suspend: true",
        "--dry-run",
    )

    for value in required_values:
        if value not in manifest:
            errors.append(
                f"Missing deployment value: {value}"
            )

    if "blackduck-harness" in manifest:
        errors.append(
            "Old blackduck-harness name remains"
        )

    if re.search(
        r"(?m)^kind:\s*Secret\s*$",
        manifest,
    ):
        errors.append(
            "Rendered base unexpectedly contains a Secret"
        )

    if not re.search(
        r'(?m)^\s*memory:\s*["\']?1Gi["\']?\s*$',
        manifest,
    ):
        errors.append(
            "Missing memory request: 1Gi"
        )

    if not re.search(
        r'(?m)^\s*memory:\s*["\']?4Gi["\']?\s*$',
        manifest,
    ):
        errors.append(
            "Missing memory limit: 4Gi"
        )

    return errors


def render_kubernetes(
    project_root: Path,
) -> tuple[str, str]:
    kubectl = shutil.which("kubectl")

    if kubectl:
        return_code, output = run_command(
            [
                kubectl,
                "kustomize",
                "deploy/base",
            ],
            cwd=project_root,
        )

        if return_code == 0:
            return output, "kubectl kustomize"

    kustomize = shutil.which("kustomize")

    if kustomize:
        return_code, output = run_command(
            [
                kustomize,
                "build",
                "deploy/base",
            ],
            cwd=project_root,
        )

        if return_code == 0:
            return output, "kustomize build"

    files = sorted(
        (project_root / "deploy" / "base").glob(
            "*.yaml"
        )
    )
    return (
        "\n---\n".join(
            path.read_text(encoding="utf-8")
            for path in files
        ),
        "source fallback",
    )


def validate_release(
    project_root: Path,
    *,
    image: str,
    build: bool,
    skip_docker: bool,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    if not skip_docker:
        if build:
            return_code, output = run_command(
                [
                    "docker",
                    "build",
                    "--tag",
                    image,
                    "--file",
                    "Dockerfile",
                    ".",
                ],
                cwd=project_root,
                timeout=900,
            )
            checks.append(
                {
                    "name": "docker-build",
                    "ok": return_code == 0,
                    "return_code": return_code,
                    "error": (
                        ""
                        if return_code == 0
                        else output[-3000:]
                    ),
                }
            )

        return_code, output = run_command(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                (
                    "id={{.Id}} "
                    "user={{.Config.User}} "
                    "entrypoint={{json .Config.Entrypoint}} "
                    "cmd={{json .Config.Cmd}}"
                ),
                image,
            ],
            cwd=project_root,
        )
        checks.append(
            {
                "name": "docker-image-config",
                "ok": (
                    return_code == 0
                    and "10001:10001" in output
                    and "blackduck-jira-pipeline" in output
                ),
                "return_code": return_code,
                "error": (
                    ""
                    if return_code == 0
                    else output[-2000:]
                ),
                "summary": (
                    output.strip()
                    if return_code == 0
                    else ""
                ),
            }
        )

        for command_name in entrypoint_names(
            project_root
        ):
            return_code, output = run_command(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    command_name,
                    image,
                    "--help",
                ],
                cwd=project_root,
                timeout=60,
            )
            checks.append(
                {
                    "name": (
                        f"container-help:{command_name}"
                    ),
                    "ok": return_code == 0,
                    "return_code": return_code,
                    "error": (
                        ""
                        if return_code == 0
                        else output[-2000:]
                    ),
                }
            )

    manifest, renderer = render_kubernetes(
        project_root
    )
    manifest_errors = validate_manifest(
        manifest
    )
    checks.append(
        {
            "name": "kubernetes-base",
            "ok": not manifest_errors,
            "renderer": renderer,
            "errors": manifest_errors,
        }
    )

    return {
        "ok": all(
            check["ok"]
            for check in checks
        ),
        "image": image,
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate Wintermute packaging, container "
            "commands, and Kubernetes defaults without "
            "saving environment secrets."
        )
    )
    parser.add_argument(
        "--project-root",
        default=str(
            Path(__file__).resolve().parents[1]
        ),
    )
    parser.add_argument(
        "--image",
        default="blackduck-wintermute:local",
    )
    parser.add_argument(
        "--build",
        action="store_true",
    )
    parser.add_argument(
        "--skip-docker",
        action="store_true",
    )
    parser.add_argument(
        "--report",
        default=(
            ".validation-results/release.json"
        ),
    )
    args = parser.parse_args()
    project_root = Path(
        args.project_root
    ).resolve()
    result = validate_release(
        project_root,
        image=args.image,
        build=args.build,
        skip_docker=args.skip_docker,
    )
    report_path = (
        project_root / args.report
    )
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
