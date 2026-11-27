from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from wintermute.paths import output_root
from wintermute.scm.onboarding.bootstrap import (
    load_verified_central_bundle,
)
from wintermute.scm.onboarding.central_bundle import (
    CentralBundleConfiguration,
    write_bundle,
)
from wintermute.scm.onboarding.template_artifacts import (
    TemplatePlanError,
    load_verified_template_plan,
)


DIGEST_PATTERN = re.compile(
    r"^sha256:[0-9a-f]{64}$"
)
INSPECT_DIGEST_PATTERN = re.compile(
    r"(?m)^Digest:\s*"
    r"(sha256:[0-9a-f]{64})\s*$"
)
MEDIA_TYPE_PATTERN = re.compile(
    r"(?m)^MediaType:\s*(\S+)\s*$"
)
PLATFORM_PATTERN = re.compile(
    r"(?m)^\s*Platform:\s*"
    r"(linux/(?:amd64|arm64))\s*$"
)
REQUIRED_PLATFORMS = {
    "linux/amd64",
    "linux/arm64",
}
MACHINE_PLATFORMS = {
    "aarch64": "linux/arm64",
    "amd64": "linux/amd64",
    "arm64": "linux/arm64",
    "x86_64": "linux/amd64",
}


def immutable_image_digest(
    image: str,
) -> str:
    selected = str(image or "").strip()

    if (
        not selected
        or selected.count("@") != 1
    ):
        raise ValueError(
            "Scan image must use an immutable "
            "repository@sha256 digest reference"
        )

    _, digest = selected.rsplit("@", 1)
    digest = digest.casefold()

    if DIGEST_PATTERN.fullmatch(
        digest
    ) is None:
        raise ValueError(
            "Scan image digest is invalid"
        )

    return digest


def run_command(
    command: list[str],
    *,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            f"Required executable was not found: "
            f"{command[0]}"
        ) from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "Command timed out: "
            + " ".join(command[:4])
        ) from error

    if completed.returncode != 0:
        detail = (
            completed.stderr
            or completed.stdout
            or "unknown error"
        ).strip()

        raise RuntimeError(
            "Command failed with exit code "
            f"{completed.returncode}: "
            f"{detail[-4000:]}"
        )

    return completed


def parse_image_inspection(
    image: str,
    output: str,
) -> dict[str, Any]:
    expected_digest = (
        immutable_image_digest(image)
    )
    digest_match = (
        INSPECT_DIGEST_PATTERN.search(
            output
        )
    )

    if digest_match is None:
        raise RuntimeError(
            "Image inspection did not report "
            "a top-level digest"
        )

    actual_digest = (
        digest_match.group(1).casefold()
    )

    if actual_digest != expected_digest:
        raise RuntimeError(
            "Image inspection digest mismatch: "
            f"expected {expected_digest}, "
            f"received {actual_digest}"
        )

    media_match = MEDIA_TYPE_PATTERN.search(
        output
    )

    if media_match is None:
        raise RuntimeError(
            "Image inspection did not report "
            "a top-level media type"
        )

    media_type = media_match.group(1)
    lowered_media_type = (
        media_type.casefold()
    )

    if (
        "image.index" not in lowered_media_type
        and "manifest.list"
        not in lowered_media_type
    ):
        raise RuntimeError(
            "Scan image is not a multi-architecture "
            f"OCI index: {media_type}"
        )

    platforms = sorted(
        set(
            PLATFORM_PATTERN.findall(
                output
            )
        )
    )
    missing = (
        REQUIRED_PLATFORMS
        - set(platforms)
    )

    if missing:
        raise RuntimeError(
            "Scan image is missing required "
            "platform(s): "
            + ", ".join(sorted(missing))
        )

    return {
        "image": image,
        "index_digest": actual_digest,
        "media_type": media_type,
        "platforms": platforms,
    }


def inspect_image(
    docker: str,
    image: str,
    *,
    timeout: float,
) -> dict[str, Any]:
    completed = run_command(
        [
            docker,
            "buildx",
            "imagetools",
            "inspect",
            image,
        ],
        timeout=timeout,
    )

    return parse_image_inspection(
        image,
        completed.stdout,
    )


def bridge_probe_source() -> str:
    return (
        "import hashlib,json,platform;"
        "digest=hashlib.sha256();"
        "stream=open("
        "'/opt/blackduck/bridge/bridge-cli',"
        "'rb');"
        "[digest.update(chunk) "
        "for chunk in iter("
        "lambda:stream.read(1048576),b'')];"
        "stream.close();"
        "print(json.dumps({"
        "'bridge_sha256':digest.hexdigest(),"
        "'machine':platform.machine()"
        "},sort_keys=True))"
    )


def parse_bridge_probe(
    output: str,
) -> dict[str, str]:
    lines = [
        line.strip()
        for line in output.splitlines()
        if line.strip()
    ]

    if not lines:
        raise RuntimeError(
            "Scan image Bridge probe returned "
            "no output"
        )

    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "Scan image Bridge probe returned "
            "invalid JSON"
        ) from error

    if not isinstance(payload, dict):
        raise RuntimeError(
            "Scan image Bridge probe result "
            "is not an object"
        )

    digest = str(
        payload.get("bridge_sha256")
        or ""
    ).casefold()
    machine = str(
        payload.get("machine")
        or ""
    ).casefold()

    if (
        len(digest) != 64
        or any(
            character
            not in "0123456789abcdef"
            for character in digest
        )
    ):
        raise RuntimeError(
            "Scan image Bridge executable "
            "digest is invalid"
        )

    image_platform = (
        MACHINE_PLATFORMS.get(machine)
    )

    if image_platform is None:
        raise RuntimeError(
            "Scan image reported an unsupported "
            f"machine architecture: {machine}"
        )

    return {
        "bridge_sha256": digest,
        "machine": machine,
        "platform": image_platform,
    }


def inspect_bridge(
    docker: str,
    image: str,
    *,
    timeout: float,
) -> dict[str, str]:
    completed = run_command(
        [
            docker,
            "run",
            "--rm",
            "--entrypoint",
            "python",
            image,
            "-c",
            bridge_probe_source(),
        ],
        timeout=timeout,
    )

    return parse_bridge_probe(
        completed.stdout
    )


def inspect_bridge_platforms(
    docker: str,
    image: str,
    *,
    timeout: float,
) -> dict[str, str]:
    checksums: dict[str, str] = {}

    for image_platform in sorted(REQUIRED_PLATFORMS):
        completed = run_command(
            [
                docker,
                "run",
                "--rm",
                "--platform",
                image_platform,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--entrypoint",
                "python",
                image,
                "-I",
                "-c",
                bridge_probe_source(),
            ],
            timeout=timeout,
        )
        probe = parse_bridge_probe(completed.stdout)

        if probe["platform"] != image_platform:
            raise RuntimeError(
                "Bridge probe architecture mismatch: "
                f"expected {image_platform}, received {probe['platform']}"
            )

        checksums[image_platform] = probe["bridge_sha256"]

    return checksums


def require_count(
    name: str,
    expected: int | None,
    actual: Any,
) -> None:
    if expected is None:
        return

    try:
        selected = int(actual)
    except (
        TypeError,
        ValueError,
    ) as error:
        raise RuntimeError(
            f"Template plan {name} count "
            "is invalid"
        ) from error

    if selected != expected:
        raise RuntimeError(
            f"Template plan {name} count "
            f"mismatch: expected {expected}, "
            f"received {selected}"
        )


def run(
    args: argparse.Namespace,
) -> int:
    image = str(args.image).strip()
    immutable_image_digest(image)
    template_plan = (
        load_verified_template_plan(
            args.template_plan
        )
    )

    if (
        template_plan.digest
        != args.expected_template_plan_digest
    ):
        raise RuntimeError(
            "Expected template-plan digest "
            "does not match the verified plan"
        )

    require_count(
        "repository",
        args.expected_repository_count,
        template_plan.plan.get(
            "repository_count"
        ),
    )
    require_count(
        "required repository",
        args.expected_required_count,
        template_plan.plan.get(
            "required_count"
        ),
    )
    require_count(
        "review repository",
        args.expected_review_count,
        template_plan.plan.get(
            "review_count"
        ),
    )

    image_inspection = inspect_image(
        args.docker,
        image,
        timeout=args.inspect_timeout,
    )
    bridge = inspect_bridge(
        args.docker,
        image,
        timeout=args.run_timeout,
    )

    if (
        bridge["platform"]
        not in image_inspection[
            "platforms"
        ]
    ):
        raise RuntimeError(
            "Locally executed scan-image platform "
            "is absent from the verified OCI index"
        )

    directory = write_bundle(
        args.output_root,
        template_plan,
        CentralBundleConfiguration(
            image=image,
            bridge_sha256=(
                json.dumps(
                    inspect_bridge_platforms(
                        args.docker,
                        image,
                        timeout=args.run_timeout,
                    ),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            ),
            gitlab_project=(
                args.gitlab_project
            ),
            gitlab_ref=(
                args.gitlab_ref
            ),
        ),
    )
    loaded = load_verified_central_bundle(
        directory
    )

    print(
        json.dumps(
            {
                "status": "succeeded",
                "template_plan_id": (
                    template_plan.plan[
                        "plan_id"
                    ]
                ),
                "template_plan_digest": (
                    template_plan.digest
                ),
                "repository_count": (
                    template_plan.plan[
                        "repository_count"
                    ]
                ),
                "required_count": (
                    template_plan.plan[
                        "required_count"
                    ]
                ),
                "review_count": (
                    template_plan.plan[
                        "review_count"
                    ]
                ),
                "scan_contract_count": (
                    template_plan.plan[
                        "scan_contract_count"
                    ]
                ),
                "image": image,
                "image_index_digest": (
                    image_inspection[
                        "index_digest"
                    ]
                ),
                "image_media_type": (
                    image_inspection[
                        "media_type"
                    ]
                ),
                "image_platforms": (
                    image_inspection[
                        "platforms"
                    ]
                ),
                "executed_platform": (
                    bridge["platform"]
                ),
                "bridge_sha256": (
                    bridge["bridge_sha256"]
                ),
                "bundle_id": (
                    loaded.bundle_id
                ),
                "bundle_digest": (
                    loaded.digest
                ),
                "registry_sha256": (
                    loaded.managed[
                        "registry_sha256"
                    ]
                ),
                "bundle_directory": str(
                    directory
                ),
                "remote_writes": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 0


def optional_count(
    parser: argparse.ArgumentParser,
    name: str,
) -> None:
    parser.add_argument(
        name,
        type=int,
    )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the immutable multi-architecture "
            "scan image and render a central bundle "
            "from one exact template plan."
        )
    )
    parser.add_argument(
        "--template-plan",
        required=True,
    )
    parser.add_argument(
        "--expected-template-plan-digest",
        required=True,
    )
    parser.add_argument(
        "--image",
        required=True,
    )
    parser.add_argument(
        "--gitlab-project",
        required=True,
    )
    parser.add_argument(
        "--gitlab-ref",
        default="main",
    )
    parser.add_argument(
        "--output-root",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "central-bundles"
        ),
    )
    parser.add_argument(
        "--docker",
        default="docker",
    )
    parser.add_argument(
        "--inspect-timeout",
        type=float,
        default=300,
    )
    parser.add_argument(
        "--run-timeout",
        type=float,
        default=300,
    )
    optional_count(
        parser,
        "--expected-repository-count",
    )
    optional_count(
        parser,
        "--expected-required-count",
    )
    optional_count(
        parser,
        "--expected-review-count",
    )
    args = parser.parse_args(argv)

    if args.inspect_timeout <= 0:
        parser.error(
            "--inspect-timeout must be positive"
        )

    if args.run_timeout <= 0:
        parser.error(
            "--run-timeout must be positive"
        )

    if (
        not args.gitlab_project.strip()
        or args.gitlab_project.count("/")
        < 1
    ):
        parser.error(
            "--gitlab-project must use "
            "namespace/project"
        )

    if not args.gitlab_ref.strip():
        parser.error(
            "--gitlab-ref must not be empty"
        )

    for name in (
        "expected_repository_count",
        "expected_required_count",
        "expected_review_count",
    ):
        value = getattr(args, name)

        if value is not None and value < 0:
            parser.error(
                f"--{name.replace('_', '-')} "
                "cannot be negative"
            )

    return args


def main(
    argv: list[str] | None = None,
) -> int:
    try:
        return run(parse_args(argv))
    except KeyboardInterrupt:
        return 130
    except (
        OSError,
        RuntimeError,
        TemplatePlanError,
        ValueError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
