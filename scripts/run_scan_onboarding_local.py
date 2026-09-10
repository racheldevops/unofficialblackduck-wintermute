#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from wintermute.scm.onboarding.template_artifacts import (
    load_verified_template_plan,
)


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def output_root() -> Path:
    root = project_root()
    configured = os.getenv(
        "WINTERMUTE_OUTPUT_DIR",
        "",
    ).strip()

    if not configured:
        return root / ".wintermute"

    selected = Path(configured).expanduser()

    return (
        selected
        if selected.is_absolute()
        else root / selected
    )


def latest_ready(
    directory: Path,
) -> Path:
    if not directory.is_dir():
        raise RuntimeError(
            f"Artifact directory does not exist: "
            f"{directory}"
        )

    candidates = sorted(
        (
            path
            for path in directory.iterdir()
            if (
                path.is_dir()
                and (path / "READY").is_file()
            )
        ),
        key=lambda path: path.name,
        reverse=True,
    )

    if not candidates:
        raise RuntimeError(
            f"No ready artifacts exist under "
            f"{directory}"
        )

    return candidates[0].resolve()


def run_command(
    label: str,
    command: list[str],
) -> int:
    print()
    print("=" * 72)
    print(label)
    print("=" * 72)
    print(" ".join(command))
    sys.stdout.flush()

    completed = subprocess.run(
        command,
        cwd=project_root(),
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        check=False,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            f"{label} exited with code "
            f"{completed.returncode}"
        )

    return completed.returncode


def scan_image() -> str:
    return os.getenv(
        "WINTERMUTE_SCAN_IMAGE",
        "blackduck-wintermute-scan:local",
    ).strip()


def bridge_sha256(
    image: str,
) -> str:
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            image,
            "-c",
            (
                "import hashlib; "
                "print(hashlib.sha256("
                "open('/opt/blackduck/bridge/"
                "bridge-cli','rb').read()"
                ").hexdigest())"
            ),
        ],
        cwd=project_root(),
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            "Could not inspect Bridge in the "
            "local scan image"
        )

    digest = completed.stdout.strip()

    if (
        len(digest) != 64
        or any(
            value
            not in "0123456789abcdef"
            for value in digest
        )
    ):
        raise RuntimeError(
            "Local Bridge executable digest "
            "is invalid"
        )

    return digest


def required_providers(
    template_plan: Path,
) -> set[str]:
    loaded = load_verified_template_plan(
        template_plan
    )

    return {
        str(value["provider"])
        for value
        in loaded.assignments[
            "assignments"
        ]
        if value[
            "onboarding_policy"
        ] == "required"
    }


def github_repository() -> str:
    organization = os.getenv(
        "GITHUB_ORG",
        "",
    ).strip()

    if not organization:
        raise RuntimeError(
            "GITHUB_ORG must be set for "
            "GitHub central rendering"
        )

    repository = os.getenv(
        "GITHUB_CENTRAL_REPOSITORY",
        (
            f"{organization}/"
            "wintermute-security-scans"
        ),
    ).strip()

    if (
        repository.count("/") != 1
        or repository.split("/", 1)[0]
        .casefold()
        != organization.casefold()
    ):
        raise RuntimeError(
            "GITHUB_CENTRAL_REPOSITORY must "
            "belong to GITHUB_ORG"
        )

    return repository


def gitlab_project() -> str:
    group = os.getenv(
        "GITLAB_GROUP",
        "",
    ).strip("/")

    if not group:
        raise RuntimeError(
            "GITLAB_GROUP must be set for "
            "GitLab central rendering"
        )

    return os.getenv(
        "GITLAB_CENTRAL_PROJECT",
        (
            f"{group}/"
            "wintermute-security-scans"
        ),
    ).strip()


def render_bundle(
    args: argparse.Namespace,
) -> int:
    output = output_root()
    template_plan = latest_ready(
        output
        / "scm"
        / "onboarding"
        / "template-plans"
    )
    providers = required_providers(
        template_plan
    )
    image = scan_image()
    command = [
        sys.executable,
        "-m",
        (
            "wintermute.scm.onboarding."
            "central_bundle_cli"
        ),
        "--template-plan",
        str(template_plan),
        "--image",
        image,
        "--bridge-sha256",
        bridge_sha256(image),
    ]

    if "github" in providers:
        checkout_sha = os.getenv(
            "GITHUB_CHECKOUT_ACTION_SHA",
            "",
        ).strip()

        if (
            len(checkout_sha) != 40
            or any(
                value
                not in "0123456789abcdef"
                for value in checkout_sha
            )
        ):
            raise RuntimeError(
                "GITHUB_CHECKOUT_ACTION_SHA must "
                "be a full lowercase commit SHA"
            )

        command.extend(
            [
                "--github-repository",
                github_repository(),
                "--github-ref",
                os.getenv(
                    "GITHUB_CENTRAL_REF",
                    "main",
                ),
                "--github-checkout-action-sha",
                checkout_sha,
            ]
        )

    if "gitlab" in providers:
        command.extend(
            [
                "--gitlab-project",
                gitlab_project(),
                "--gitlab-ref",
                os.getenv(
                    "GITLAB_CENTRAL_REF",
                    "main",
                ),
            ]
        )

    return run_command(
        "Render local central scan bundle",
        command,
    )


def contract_dry_run(
    args: argparse.Namespace,
) -> int:
    del args
    output = output_root()
    bundle = latest_ready(
        output
        / "scm"
        / "onboarding"
        / "central-bundles"
    )
    registry = (
        bundle
        / "registry"
        / "scan-registry.json"
    )
    registry_digest = hashlib.sha256(
        registry.read_bytes()
    ).hexdigest()
    payload = json.loads(
        registry.read_text(
            encoding="utf-8"
        )
    )
    assignments = payload.get(
        "assignments"
    )

    if (
        not isinstance(assignments, list)
        or not assignments
    ):
        raise RuntimeError(
            "Central scan registry has no "
            "approved assignments"
        )

    assignment = assignments[0]
    image = scan_image()
    command = [
        "docker",
        "run",
        "--rm",
        "--mount",
        (
            "type=bind,"
            f"src={registry.resolve()},"
            "dst=/tmp/scan-registry.json,"
            "readonly"
        ),
        "--mount",
        (
            "type=bind,"
            f"src={project_root()},"
            "dst=/workspace,"
            "readonly"
        ),
        image,
        "--registry",
        "/tmp/scan-registry.json",
        "--expected-registry-sha256",
        registry_digest,
        "--scm-provider",
        str(assignment["provider"]),
        "--scm-provider-instance",
        str(
            assignment[
                "provider_instance"
            ]
        ),
        "--scm-repository-id",
        str(
            assignment["repository_id"]
        ),
        "--commit-sha",
        "local-contract-smoke",
        "--source-root",
        "/workspace",
        "--expected-bridge-sha256",
        bridge_sha256(image),
        "--mode",
        "dry-run",
    ]

    return run_command(
        "Run local scan contract dry-run",
        command,
    )


def bootstrap_plan(
    args: argparse.Namespace,
) -> int:
    del args
    output = output_root()
    bundle = latest_ready(
        output
        / "scm"
        / "onboarding"
        / "central-bundles"
    )
    providers: set[str] = set()

    if (
        bundle
        / ".github"
        / "workflows"
        / "wintermute-security.yml"
    ).is_file():
        providers.add("github")

    if (
        bundle
        / "templates"
        / "wintermute-security.yml"
    ).is_file():
        providers.add("gitlab")

    command = [
        sys.executable,
        "-m",
        (
            "wintermute.scm.onboarding."
            "bootstrap_cli"
        ),
        "plan",
        "--bundle",
        str(bundle),
    ]

    if "github" in providers:
        repository = github_repository()
        owner, name = repository.split(
            "/",
            1,
        )
        command.extend(
            [
                "--github-organization",
                owner,
                "--github-repository",
                name,
                "--github-default-branch",
                os.getenv(
                    "GITHUB_CENTRAL_REF",
                    "main",
                ),
            ]
        )

    if "gitlab" in providers:
        group = os.getenv(
            "GITLAB_GROUP",
            "",
        ).strip("/")

        if not group:
            raise RuntimeError(
                "GITLAB_GROUP must be set"
            )

        project = gitlab_project()

        if not project.startswith(
            f"{group}/"
        ):
            raise RuntimeError(
                "GITLAB_CENTRAL_PROJECT must "
                "belong to GITLAB_GROUP"
            )

        command.extend(
            [
                "--gitlab-group",
                group,
                "--gitlab-project",
                project.rsplit("/", 1)[1],
                "--gitlab-default-branch",
                os.getenv(
                    "GITLAB_CENTRAL_REF",
                    "main",
                ),
            ]
        )

    return run_command(
        "Create initialize-only bootstrap plan",
        command,
    )


def bootstrap_dry_run(
    args: argparse.Namespace,
) -> int:
    output = output_root()
    plan = latest_ready(
        output
        / "scm"
        / "onboarding"
        / "bootstrap-plans"
    )
    command = [
        sys.executable,
        "-m",
        (
            "wintermute.scm.onboarding."
            "bootstrap_cli"
        ),
        "execute",
        "--plan",
        str(plan),
        "--dry-run",
    ]

    if args.insecure:
        command.append("--insecure")
    elif args.ca_bundle:
        command.extend(
            [
                "--ca-bundle",
                args.ca_bundle,
            ]
        )

    return run_command(
        "Run initialize-only bootstrap dry-run",
        command,
    )


def all_dry_run(
    args: argparse.Namespace,
) -> int:
    render_bundle(args)
    contract_dry_run(args)
    bootstrap_plan(args)
    return bootstrap_dry_run(args)


def add_tls(
    parser: argparse.ArgumentParser,
) -> None:
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument(
        "--ca-bundle",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run local central scan onboarding "
            "validation stages."
        )
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    for name in (
        "render-bundle",
        "contract-dry-run",
        "bootstrap-plan",
        "bootstrap-dry-run",
        "all-dry-run",
    ):
        selected = commands.add_parser(name)
        add_tls(selected)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    operations = {
        "render-bundle": render_bundle,
        "contract-dry-run": (
            contract_dry_run
        ),
        "bootstrap-plan": (
            bootstrap_plan
        ),
        "bootstrap-dry-run": (
            bootstrap_dry_run
        ),
        "all-dry-run": all_dry_run,
    }

    try:
        return operations[
            args.command
        ](args)
    except KeyboardInterrupt:
        return 130
    except (
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
