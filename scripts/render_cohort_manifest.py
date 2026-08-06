#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


IMAGE_TARGETS = (
    "source",
    "jira",
    "datadog",
)
VALID_MODES = {
    "dry-run",
    "apply",
}
TAG_RE = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)
NAMESPACE_RE = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$"
)


def validate_options(
    *,
    registry_host: str,
    registry_repository: str,
    image_tag: str,
    namespace: str,
    jira_mode: str,
    datadog_mode: str,
    confirm_apply: bool,
    retain_cohorts: int,
) -> None:
    if not registry_host.strip():
        raise RuntimeError(
            "registry_host must not be empty"
        )

    if "://" in registry_host:
        raise RuntimeError(
            "registry_host must not include a URL scheme"
        )

    if not registry_repository.strip():
        raise RuntimeError(
            "registry_repository must not be empty"
        )

    if (
        not TAG_RE.fullmatch(image_tag)
        or image_tag in {"latest", "replace-me"}
    ):
        raise RuntimeError(
            "image_tag must be an immutable tag"
        )

    if (
        len(namespace) > 63
        or not NAMESPACE_RE.fullmatch(namespace)
    ):
        raise RuntimeError(
            f"Invalid Kubernetes namespace: {namespace!r}"
        )

    if jira_mode not in VALID_MODES:
        raise RuntimeError(
            f"Invalid Jira mode: {jira_mode}"
        )

    if datadog_mode not in VALID_MODES:
        raise RuntimeError(
            f"Invalid Datadog mode: {datadog_mode}"
        )

    if (
        "apply" in {jira_mode, datadog_mode}
        and not confirm_apply
    ):
        raise RuntimeError(
            "Apply mode requires confirm_apply"
        )

    if retain_cohorts < 1:
        raise RuntimeError(
            "retain_cohorts must be greater than zero"
        )


def image_names(
    registry_host: str,
    registry_repository: str,
    image_tag: str,
) -> dict[str, str]:
    host = registry_host.strip().strip("/")
    repository = (
        registry_repository.strip().strip("/")
    )

    return {
        target: (
            f"{host}/{repository}-{target}:"
            f"{image_tag}"
        )
        for target in IMAGE_TARGETS
    }


def workflow_image_patch(
    images: dict[str, str],
) -> str:
    operations = (
        (
            "/spec/templates/1/script/image",
            images["source"],
        ),
        (
            "/spec/templates/2/container/image",
            images["source"],
        ),
        (
            "/spec/templates/3/container/image",
            images["jira"],
        ),
        (
            "/spec/templates/4/container/image",
            images["datadog"],
        ),
    )

    return "\n".join(
        [
            line
            for path, image in operations
            for line in (
                "- op: replace",
                f"  path: {path}",
                f"  value: {image}",
            )
        ]
    ) + "\n"


def schedule_patch(
    *,
    schedule: str,
    timezone: str,
    suspend: bool,
    jira_mode: str,
    datadog_mode: str,
    confirm_apply: bool,
    retain_cohorts: int,
) -> str:
    return f"""apiVersion: argoproj.io/v1alpha1
kind: CronWorkflow
metadata:
  name: blackduck-wintermute-cohort
spec:
  schedule: {json.dumps(schedule)}
  timezone: {json.dumps(timezone)}
  suspend: {str(suspend).lower()}
  concurrencyPolicy: Forbid
  workflowSpec:
    arguments:
      parameters:
        - name: jira-mode
          value: {jira_mode}
        - name: datadog-mode
          value: {datadog_mode}
        - name: confirm-apply
          value: {json.dumps(str(confirm_apply).lower())}
        - name: retain-cohorts
          value: {json.dumps(str(retain_cohorts))}
"""


def render_manifest(
    project_root: Path,
    *,
    output: Path,
    registry_host: str,
    registry_repository: str,
    image_tag: str,
    namespace: str,
    jira_mode: str,
    datadog_mode: str,
    confirm_apply: bool,
    retain_cohorts: int,
    schedule: str,
    timezone: str,
    suspend: bool,
    kubectl: str = "kubectl",
) -> None:
    validate_options(
        registry_host=registry_host,
        registry_repository=registry_repository,
        image_tag=image_tag,
        namespace=namespace,
        jira_mode=jira_mode,
        datadog_mode=datadog_mode,
        confirm_apply=confirm_apply,
        retain_cohorts=retain_cohorts,
    )
    source_overlay = (
        project_root
        / "deploy"
        / "overlays"
        / "customer-cohort"
    )
    overlays_root = source_overlay.parent

    if not source_overlay.is_dir():
        raise RuntimeError(
            f"Customer cohort overlay is missing: "
            f"{source_overlay}"
        )

    temporary_directory = Path(
        tempfile.mkdtemp(
            prefix=".cohort-render-",
            dir=overlays_root,
        )
    )

    try:
        shutil.copytree(
            source_overlay,
            temporary_directory,
            dirs_exist_ok=True,
        )
        images = image_names(
            registry_host,
            registry_repository,
            image_tag,
        )
        (
            temporary_directory
            / "workflow-images-patch.yaml"
        ).write_text(
            workflow_image_patch(images),
            encoding="utf-8",
        )
        (
            temporary_directory
            / "schedule-patch.yaml"
        ).write_text(
            schedule_patch(
                schedule=schedule,
                timezone=timezone,
                suspend=suspend,
                jira_mode=jira_mode,
                datadog_mode=datadog_mode,
                confirm_apply=confirm_apply,
                retain_cohorts=retain_cohorts,
            ),
            encoding="utf-8",
        )

        kustomization_path = (
            temporary_directory
            / "kustomization.yaml"
        )
        kustomization_text = (
            kustomization_path.read_text(
                encoding="utf-8"
            )
        )
        kustomization_text, namespace_count = re.subn(
            r"(?m)^namespace:\s*[^\s#]+\s*$",
            f"namespace: {namespace}",
            kustomization_text,
            count=1,
        )

        if namespace_count != 1:
            raise RuntimeError(
                "Customer overlay namespace field "
                "was not found"
            )

        kustomization_path.write_text(
            kustomization_text,
            encoding="utf-8",
        )

        namespace_path = (
            temporary_directory
            / "namespace.yaml"
        )
        namespace_text = namespace_path.read_text(
            encoding="utf-8"
        )
        namespace_text, resource_name_count = re.subn(
            r"(?m)^  name:\s*[^\s#]+\s*$",
            f"  name: {namespace}",
            namespace_text,
            count=1,
        )

        if resource_name_count != 1:
            raise RuntimeError(
                "Namespace resource name was not found"
            )

        namespace_path.write_text(
            namespace_text,
            encoding="utf-8",
        )

        completed = subprocess.run(
            [
                kubectl,
                "kustomize",
                str(temporary_directory),
            ],
            cwd=project_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )

        if completed.returncode != 0:
            raise RuntimeError(
                "Kustomize render failed: "
                + completed.stderr.strip()
            )

        output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        temporary_output = output.with_name(
            f"{output.name}.tmp"
        )
        temporary_output.write_text(
            completed.stdout,
            encoding="utf-8",
        )
        os.replace(
            temporary_output,
            output,
        )

    finally:
        shutil.rmtree(
            temporary_directory,
            ignore_errors=True,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Render an immutable customer cohort "
            "Kubernetes manifest."
        )
    )
    parser.add_argument(
        "--project-root",
        default=str(
            Path(__file__).resolve().parents[1]
        ),
    )
    parser.add_argument(
        "--output",
        default=(
            ".validation-results/"
            "kubernetes-cohort-rendered.yaml"
        ),
    )
    parser.add_argument(
        "--registry-host",
        required=True,
    )
    parser.add_argument(
        "--registry-repository",
        required=True,
    )
    parser.add_argument(
        "--image-tag",
        required=True,
    )
    parser.add_argument(
        "--namespace",
        default="blackduck-wintermute",
    )
    parser.add_argument(
        "--jira-mode",
        choices=sorted(VALID_MODES),
        default="dry-run",
    )
    parser.add_argument(
        "--datadog-mode",
        choices=sorted(VALID_MODES),
        default="dry-run",
    )
    parser.add_argument(
        "--confirm-apply",
        action="store_true",
    )
    parser.add_argument(
        "--retain-cohorts",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--schedule",
        default="0 2 * * *",
    )
    parser.add_argument(
        "--timezone",
        default="Etc/UTC",
    )
    parser.add_argument(
        "--enable-schedule",
        action="store_true",
    )
    parser.add_argument(
        "--kubectl",
        default="kubectl",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        render_manifest(
            Path(args.project_root).resolve(),
            output=Path(args.output),
            registry_host=args.registry_host,
            registry_repository=(
                args.registry_repository
            ),
            image_tag=args.image_tag,
            namespace=args.namespace,
            jira_mode=args.jira_mode,
            datadog_mode=args.datadog_mode,
            confirm_apply=args.confirm_apply,
            retain_cohorts=args.retain_cohorts,
            schedule=args.schedule,
            timezone=args.timezone,
            suspend=not args.enable_schedule,
            kubectl=args.kubectl,
        )
    except (
        OSError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2

    print(f"Rendered manifest: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
