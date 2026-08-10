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
from urllib.parse import urlsplit


TAG_RE = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)
NAMESPACE_RE = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$"
)
STORAGE_RE = re.compile(
    r"^[1-9][0-9]*(?:Mi|Gi|Ti)$"
)


def replace_once(
    text: str,
    pattern: str,
    replacement: str,
    field: str,
) -> str:
    result, count = re.subn(
        pattern,
        replacement,
        text,
        count=1,
    )

    if count != 1:
        raise RuntimeError(
            f"Expected one {field}; found {count}"
        )

    return result


def validate_options(
    args: argparse.Namespace,
) -> None:
    if (
        not args.registry_host
        or "://" in args.registry_host
    ):
        raise RuntimeError(
            "registry-host must be a hostname"
        )

    if not args.registry_repository.strip("/"):
        raise RuntimeError(
            "registry-repository must not be empty"
        )

    if (
        not TAG_RE.fullmatch(args.image_tag)
        or args.image_tag
        in {"latest", "replace-me"}
    ):
        raise RuntimeError(
            "image-tag must be immutable"
        )

    if (
        len(args.namespace) > 63
        or not NAMESPACE_RE.fullmatch(
            args.namespace
        )
    ):
        raise RuntimeError(
            f"Invalid namespace: {args.namespace!r}"
        )

    parsed_jira = urlsplit(args.jira_url)

    if (
        parsed_jira.scheme != "https"
        or not parsed_jira.netloc
        or parsed_jira.username is not None
        or parsed_jira.password is not None
    ):
        raise RuntimeError(
            "jira-url must be an HTTPS URL"
        )

    if not args.jira_project_key.strip():
        raise RuntimeError(
            "jira-project-key must not be empty"
        )

    if not STORAGE_RE.fullmatch(
        args.pvc_size
    ):
        raise RuntimeError(
            "pvc-size must use Mi, Gi, or Ti"
        )

    for name in (
        "workers",
        "parent_workers",
        "rollup_workers",
    ):
        value = int(getattr(args, name))

        if not 1 <= value <= 8:
            raise RuntimeError(
                f"{name.replace('_', '-')} "
                "must be between 1 and 8"
            )

    if args.pipeline_mode == "apply":
        if not args.confirm_apply:
            raise RuntimeError(
                "Apply mode requires --confirm-apply"
            )

        if args.max_create < 1:
            raise RuntimeError(
                "max-create must be positive"
            )


def patch_argument(
    text: str,
    flag: str,
    value: str,
) -> str:
    lines = text.splitlines()
    indexes = [
        index
        for index, line in enumerate(lines)
        if line.strip() == f"- {flag}"
    ]

    if len(indexes) != 1:
        raise RuntimeError(
            f"Expected one {flag} argument; "
            f"found {len(indexes)}"
        )

    value_index = indexes[0] + 1

    if value_index >= len(lines):
        raise RuntimeError(
            f"{flag} has no value"
        )

    indentation = lines[value_index][
        : len(lines[value_index])
        - len(lines[value_index].lstrip())
    ]
    lines[value_index] = (
        f'{indentation}- "{value}"'
    )

    return "\n".join(lines) + "\n"


def patch_mode(
    text: str,
    mode: str,
    max_create: int,
) -> str:
    lines = text.splitlines()
    mode_indexes = [
        index
        for index, line in enumerate(lines)
        if line.strip()
        in {"- --dry-run", "- --apply"}
    ]

    if len(mode_indexes) != 1:
        raise RuntimeError(
            "Expected exactly one pipeline mode argument"
        )

    index = mode_indexes[0]
    indentation = lines[index][
        : len(lines[index])
        - len(lines[index].lstrip())
    ]
    lines[index] = (
        f"{indentation}- --{mode}"
    )
    max_indexes = [
        current
        for current, line in enumerate(lines)
        if line.strip() == "- --max-create"
    ]

    if len(max_indexes) > 1:
        raise RuntimeError(
            "Multiple --max-create arguments found"
        )

    if mode == "apply":
        if max_indexes:
            value_index = max_indexes[0] + 1
            lines[value_index] = (
                f'{indentation}- "{max_create}"'
            )
        else:
            lines[index + 1:index + 1] = [
                f"{indentation}- --max-create",
                f'{indentation}- "{max_create}"',
            ]
    elif max_indexes:
        max_index = max_indexes[0]
        del lines[
            max_index:max_index + 2
        ]

    return "\n".join(lines) + "\n"


def patch_pvc(
    deployment_root: Path,
    size: str,
) -> None:
    base_root = deployment_root / "base"

    if not base_root.is_dir():
        raise RuntimeError(
            f"Base deployment directory is missing: {base_root}"
        )

    candidates: list[Path] = []

    for pattern in ("*.yaml", "*.yml"):
        for candidate in base_root.rglob(pattern):
            text = candidate.read_text(
                encoding="utf-8"
            )

            if (
                re.search(
                    r"(?m)^kind:\s*"
                    r"PersistentVolumeClaim\s*$",
                    text,
                )
                and re.search(
                    r"(?m)^\s*name:\s*"
                    r"blackduck-wintermute-data\s*$",
                    text,
                )
            ):
                candidates.append(candidate)

    if len(candidates) != 1:
        relative = [
            str(candidate.relative_to(deployment_root))
            for candidate in candidates
        ]
        raise RuntimeError(
            "Expected one non-Argo Wintermute PVC manifest "
            f"under deploy/base; found {len(candidates)}: "
            f"{relative}"
        )

    pvc_path = candidates[0]
    text = pvc_path.read_text(
        encoding="utf-8"
    )
    text = replace_once(
        text,
        r"(?m)^(\s*storage:\s*).+$",
        rf"\g<1>{size}",
        "PVC storage request",
    )
    pvc_path.write_text(
        text,
        encoding="utf-8",
    )

def render(
    args: argparse.Namespace,
) -> None:
    validate_options(args)
    project_root = Path(
        args.project_root
    ).resolve()
    source_deploy = (
        project_root / "deploy"
    )

    if not source_deploy.is_dir():
        raise RuntimeError(
            f"Deployment directory is missing: "
            f"{source_deploy}"
        )

    temporary_root = Path(
        tempfile.mkdtemp(
            prefix="wintermute-jira-"
        )
    )

    try:
        deployment_root = (
            temporary_root / "deploy"
        )
        shutil.copytree(
            source_deploy,
            deployment_root,
        )
        overlay = (
            deployment_root
            / "overlays"
            / "customer"
        )
        kustomization = (
            overlay / "kustomization.yaml"
        )
        namespace_file = (
            overlay / "namespace.yaml"
        )
        cronjob = (
            overlay / "cronjob-patch.yaml"
        )
        jira_config = (
            overlay
            / "jira-rollup-config.json"
        )

        for path in (
            kustomization,
            namespace_file,
            cronjob,
            jira_config,
        ):
            if not path.is_file():
                raise RuntimeError(
                    f"Customer overlay is incomplete: "
                    f"{path}"
                )

        text = kustomization.read_text(
            encoding="utf-8"
        )
        text = replace_once(
            text,
            r"(?m)^namespace:\s*.*$",
            f"namespace: {args.namespace}",
            "kustomization namespace",
        )
        image_name = (
            f"{args.registry_host.strip('/')}/"
            f"{args.registry_repository.strip('/')}"
        )
        text = replace_once(
            text,
            r"(?m)^(\s*newName:)\s*.*$",
            rf"\1 {image_name}",
            "image newName",
        )
        text = replace_once(
            text,
            r"(?m)^(\s*newTag:)\s*.*$",
            rf"\1 {args.image_tag}",
            "image newTag",
        )
        kustomization.write_text(
            text,
            encoding="utf-8",
        )

        text = namespace_file.read_text(
            encoding="utf-8"
        )
        text = replace_once(
            text,
            r"(?m)^  name:\s*.*$",
            f"  name: {args.namespace}",
            "namespace resource name",
        )
        namespace_file.write_text(
            text,
            encoding="utf-8",
        )

        text = cronjob.read_text(
            encoding="utf-8"
        )
        text = replace_once(
            text,
            r'(?m)^  schedule:\s*.*$',
            f"  schedule: "
            f"{json.dumps(args.schedule)}",
            "CronJob schedule",
        )
        text = replace_once(
            text,
            r'(?m)^  timeZone:\s*.*$',
            f"  timeZone: "
            f"{json.dumps(args.timezone)}",
            "CronJob timezone",
        )
        text = replace_once(
            text,
            r"(?m)^  suspend:\s*"
            r"(?:true|false)\s*$",
            (
                "  suspend: "
                + str(
                    not args.enable_schedule
                ).lower()
            ),
            "CronJob suspension",
        )
        text = patch_mode(
            text,
            args.pipeline_mode,
            args.max_create,
        )

        for flag, value in (
            (
                "--workers",
                args.workers,
            ),
            (
                "--parent-workers",
                args.parent_workers,
            ),
            (
                "--rollup-workers",
                args.rollup_workers,
            ),
        ):
            text = patch_argument(
                text,
                flag,
                str(value),
            )

        cronjob.write_text(
            text,
            encoding="utf-8",
        )

        payload = json.loads(
            jira_config.read_text(
                encoding="utf-8"
            )
        )
        jira = payload.setdefault(
            "jira",
            {},
        )
        jira["url"] = (
            args.jira_url.rstrip("/")
        )
        jira["project_key"] = (
            args.jira_project_key
        )
        jira["auth_mode"] = "basic"
        jira["verify_tls"] = (
            not args.jira_insecure
        )
        jira_config.write_text(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        patch_pvc(
            deployment_root,
            args.pvc_size,
        )

        completed = subprocess.run(
            [
                args.kubectl,
                "kustomize",
                str(overlay),
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
                "Kustomize failed: "
                + completed.stderr.strip()
            )

        manifest = completed.stdout
        expected_image = (
            f"{image_name}:{args.image_tag}"
        )

        for value in (
            "kind: CronJob",
            "kind: PersistentVolumeClaim",
            "name: blackduck-jira-pipeline",
            f"image: {expected_image}",
            f"storage: {args.pvc_size}",
            f"- --{args.pipeline_mode}",
        ):
            if value not in manifest:
                raise RuntimeError(
                    "Rendered manifest is missing: "
                    f"{value}"
                )

        for forbidden in (
            "kind: Workflow",
            "kind: WorkflowTemplate",
            "kind: CronWorkflow",
            "kind: Secret",
            "registry.invalid",
            ":replace-me",
        ):
            if forbidden in manifest:
                raise RuntimeError(
                    "Rendered manifest contains "
                    f"forbidden value: {forbidden}"
                )

        if (
            not args.enable_schedule
            and "suspend: true"
            not in manifest
        ):
            raise RuntimeError(
                "Rendered CronJob is not suspended"
            )

        output = Path(args.output)
        output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        temporary = output.with_name(
            f"{output.name}.tmp"
        )
        temporary.write_text(
            manifest,
            encoding="utf-8",
        )
        os.replace(
            temporary,
            output,
        )

    finally:
        shutil.rmtree(
            temporary_root,
            ignore_errors=True,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Render the non-Argo Black Duck to Jira "
            "CronJob deployment."
        )
    )
    parser.add_argument(
        "--project-root",
        default=str(
            Path(__file__).resolve().parents[2]
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
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
        "--jira-url",
        required=True,
    )
    parser.add_argument(
        "--jira-project-key",
        required=True,
    )
    parser.add_argument(
        "--jira-insecure",
        action="store_true",
    )
    parser.add_argument(
        "--pipeline-mode",
        choices=(
            "dry-run",
            "apply",
        ),
        default="dry-run",
    )
    parser.add_argument(
        "--confirm-apply",
        action="store_true",
    )
    parser.add_argument(
        "--max-create",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--pvc-size",
        default="5Gi",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--parent-workers",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--rollup-workers",
        type=int,
        default=2,
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
        render(args)
    except (
        OSError,
        RuntimeError,
        ValueError,
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
