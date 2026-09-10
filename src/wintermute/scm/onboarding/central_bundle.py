from __future__ import annotations

import hashlib
import json
import os
import shutil
import shlex
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from wintermute.ai.models import (
    stable_digest,
)
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.scm.onboarding.template_artifacts import (
    LoadedTemplatePlan,
)


COMMIT_SHA_LENGTH = 40
BUNDLE_RENDERER_VERSION = 3


@dataclass(frozen=True)
class CentralBundleConfiguration:
    image: str
    bridge_sha256: str
    github_repository: str = ""
    github_ref: str = ""
    github_checkout_action_sha: str = ""
    github_runner: str = "ubuntu-latest"
    gitlab_project: str = ""
    gitlab_ref: str = "main"
    gitlab_insecure: bool = False

    def validate(self) -> None:
        if (
            not self.image
            or ":latest" in self.image
            or "replace-me" in self.image
        ):
            raise ValueError(
                "Central scan image must use "
                "an immutable reference"
            )

        from wintermute.scan.security import bridge_checksums

        bridge_checksums(self.bridge_sha256)

        if type(self.gitlab_insecure) is not bool:
            raise ValueError(
                "gitlab_insecure must be boolean"
            )

        if self.github_repository:
            if (
                self.github_repository.count("/")
                != 1
            ):
                raise ValueError(
                    "GitHub central repository "
                    "must use owner/name"
                )

            if (
                len(
                    self.github_checkout_action_sha
                )
                != COMMIT_SHA_LENGTH
                or any(
                    value
                    not in "0123456789abcdef"
                    for value
                    in self
                    .github_checkout_action_sha
                    .casefold()
                )
            ):
                raise ValueError(
                    "GitHub checkout action must "
                    "use a full commit SHA"
                )

            if not self.github_ref:
                raise ValueError(
                    "GitHub central ref is required"
                )

        if (
            self.gitlab_project
            and self.gitlab_project.count("/")
            < 1
        ):
            raise ValueError(
                "GitLab central project must "
                "use namespace/project"
            )


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def bundle_id(
    fingerprint: str = "",
) -> str:
    if fingerprint:
        digest = stable_digest(
            {
                "renderer_version": (
                    BUNDLE_RENDERER_VERSION
                ),
                "bundle": fingerprint,
            }
        ).split(":", 1)[1][:20]

        return (
            "central-scan-bundle-"
            f"{digest}"
        )

    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-central-scan-bundle-"
        + uuid.uuid4().hex[:12]
    )


def required_assignments(
    template_plan: LoadedTemplatePlan,
) -> list[dict[str, Any]]:
    return [
        dict(value)
        for value
        in template_plan.assignments[
            "assignments"
        ]
        if value["onboarding_policy"]
        == "required"
    ]


def runtime_registry(
    template_plan: LoadedTemplatePlan,
) -> dict[str, Any]:
    assignments = required_assignments(
        template_plan
    )
    used_ids = {
        value["scan_contract_id"]
        for value in assignments
    }
    contracts = [
        dict(value)
        for value
        in template_plan.contracts[
            "contracts"
        ]
        if value["scan_contract_id"]
        in used_ids
    ]

    return {
        "schema_version": 1,
        "source_template_plan_id": (
            template_plan.plan["plan_id"]
        ),
        "source_template_plan_digest": (
            template_plan.digest
        ),
        "contracts": sorted(
            contracts,
            key=lambda value: value[
                "scan_contract_id"
            ],
        ),
        "assignments": sorted(
            [
                {
                    "provider": (
                        value["provider"]
                    ),
                    "provider_instance": (
                        value[
                            "provider_instance"
                        ]
                    ),
                    "repository_id": str(
                        value["repository_id"]
                    ),
                    "scan_contract_id": (
                        value[
                            "scan_contract_id"
                        ]
                    ),
                }
                for value in assignments
            ],
            key=lambda value: (
                value["provider"],
                value[
                    "provider_instance"
                ],
                value["repository_id"],
            ),
        ),
    }


def registry_bytes(
    registry: dict[str, Any],
) -> bytes:
    return (
        json.dumps(
            registry,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def gitlab_image_lines(
    image: str,
) -> list[str]:
    return [
        "  image:",
        (
            "    name: "
            + json.dumps(image)
        ),
        '    entrypoint: [""]',
    ]


def render_github_workflow(
    configuration: CentralBundleConfiguration,
    registry_sha256: str,
) -> str:
    checkout = (
        "actions/checkout@"
        + configuration
        .github_checkout_action_sha
    )

    return "\n".join(
        [
            "name: Wintermute Security Scan",
            "",
            "on:",
            "  push:",
            "  pull_request:",
            "  workflow_dispatch:",
            "",
            "permissions:",
            "  contents: read",
            "",
            "concurrency:",
            (
                "  group: wintermute-security-"
                "${{ github.repository_id }}-"
                "${{ github.ref }}"
            ),
            "  cancel-in-progress: true",
            "",
            "jobs:",
            "  security-scan:",
            (
                "    if: github.repository != "
                + json.dumps(
                    configuration
                    .github_repository
                )
            ),
            (
                "    runs-on: "
                + json.dumps(
                    configuration
                    .github_runner
                )
            ),
            "    timeout-minutes: 90",
            "    container:",
            (
                "      image: "
                + json.dumps(
                    configuration.image
                )
            ),
            "    steps:",
            (
                "      - uses: "
                + checkout
            ),
            "        with:",
            "          path: workspace",
            (
                "      - uses: "
                + checkout
            ),
            "        with:",
            (
                "          repository: "
                + json.dumps(
                    configuration
                    .github_repository
                )
            ),
            (
                "          ref: "
                + json.dumps(
                    configuration.github_ref
                )
            ),
            (
                "          token: "
                "${{ secrets."
                "WINTERMUTE_CENTRAL_READ_TOKEN }}"
            ),
            (
                "          path: "
                ".wintermute-central"
            ),
            (
                "      - name: Run approved "
                "security scan"
            ),
            "        env:",
            "          SCM_PROVIDER: github",
            (
                "          SCM_PROVIDER_INSTANCE: "
                "${{ github.api_url }}"
            ),
            (
                "          SCM_REPOSITORY_ID: "
                "${{ github.repository_id }}"
            ),
            (
                "          SCM_COMMIT_SHA: "
                "${{ github.sha }}"
            ),
            (
                "          BLACKDUCK_URL: "
                "${{ vars.BLACKDUCK_URL }}"
            ),
            (
                "          BLACKDUCK_API_TOKEN: "
                "${{ secrets."
                "BLACKDUCK_API_TOKEN }}"
            ),
            (
                "          WINTERMUTE_SCAN_MODE: "
                "${{ vars."
                "WINTERMUTE_SCAN_MODE }}"
            ),
            (
                "          BLACKDUCK_BRIDGE_SHA256: "
                + json.dumps(
                    configuration
                    .bridge_sha256
                )
            ),
            "        run: >-",
            (
                "          blackduck-wintermute-scan"
            ),
            (
                "          --registry "
                ".wintermute-central/"
                "registry/scan-registry.json"
            ),
            (
                "          --expected-registry-sha256 "
                + registry_sha256
            ),
            (
                "          --source-root workspace"
            ),
            "          --confirm-execute",
            "",
        ]
    )


def render_gitlab_template(
    configuration: CentralBundleConfiguration,
    registry_sha256: str,
) -> str:
    project = quote(
        configuration.gitlab_project,
        safe="",
    )
    registry_path = quote(
        "registry/scan-registry.json",
        safe="",
    )
    reference = quote(
        configuration.gitlab_ref,
        safe="",
    )

    return "\n".join(
        [
            "wintermute_security_scan:",
            "  stage: test",
            *gitlab_image_lines(
                configuration.image
            ),
            "  timeout: 90m",
            "  variables:",
            (
                "    WINTERMUTE_SCAN_MODE: "
                '"dry-run"'
            ),
            "  before_script:",
            "    - >-",
            (
                "      python -m "
                "wintermute.scan.fetch"
            ),
            (
                "      --url "
                '"${CI_API_V4_URL}/projects/'
                f"{project}/repository/files/"
                f"{registry_path}/raw?ref="
                f'{reference}"'
            ),
            (
                "      --output "
                "/tmp/wintermute-scan-registry.json"
            ),
            (
                "      --expected-sha256 "
                + registry_sha256
            ),
            "  script:",
            "    - >-",
            (
                "      blackduck-wintermute-scan"
            ),
            (
                "      --registry "
                "/tmp/wintermute-scan-registry.json"
            ),
            (
                "      --expected-registry-sha256 "
                + registry_sha256
            ),
            "      --scm-provider gitlab",
            (
                "      --scm-provider-instance "
                '"${CI_SERVER_HOST}"'
            ),
            (
                "      --scm-repository-id "
                '"${CI_PROJECT_ID}"'
            ),
            (
                "      --commit-sha "
                '"${CI_COMMIT_SHA}"'
            ),
            (
                "      --source-root "
                '"${CI_PROJECT_DIR}"'
            ),
            (
                "      --expected-bridge-sha256 "
                + shlex.quote(configuration.bridge_sha256)
            ),
            (
                "      --mode "
                '"${WINTERMUTE_SCAN_MODE}"'
            ),
            "      --confirm-execute",
            "  rules:",
            "    - if: '$CI_COMMIT_SHA'",
            "",
        ]
    )


def render_gitlab_launcher(
    configuration: CentralBundleConfiguration,
    registry_sha256: str,
) -> str:
    lines = [
        "stages:",
        "  - security-scan",
        "",
        "workflow:",
        "  rules:",
        (
            "    - if: '$CI_PIPELINE_SOURCE "
            '== "web"\''
        ),
        (
            "    - if: '$CI_PIPELINE_SOURCE "
            '== "api"\''
        ),
        (
            "    - if: '$CI_PIPELINE_SOURCE "
            '== "trigger"\''
        ),
        "    - when: never",
        "",
        "variables:",
        '  TARGET_PROJECT_ID: ""',
        '  TARGET_COMMIT_SHA: ""',
        '  TARGET_REF: ""',
        (
            "  WINTERMUTE_SCAN_MODE: "
            '"dry-run"'
        ),
        (
            "  WINTERMUTE_SCAN_CONFIRMATION: "
            '""'
        ),
        "  GIT_STRATEGY: fetch",
        '  GIT_DEPTH: "1"',
        "",
        "wintermute_central_scan:",
        "  stage: security-scan",
        *gitlab_image_lines(
            configuration.image
        ),
        "  timeout: 90m",
        "  interruptible: false",
        (
            "  resource_group: "
            '"wintermute-${TARGET_PROJECT_ID}-'
            '${TARGET_COMMIT_SHA}"'
        ),
        "  script:",
        "    - >-",
        (
            "      python -m "
            "wintermute.scan.launcher"
        ),
        (
            "      --gitlab-api-url "
            '"${CI_API_V4_URL}"'
        ),
        (
            "      --project-id "
            '"${TARGET_PROJECT_ID}"'
        ),
        (
            "      --commit-sha "
            '"${TARGET_COMMIT_SHA}"'
        ),
        (
            "      --registry "
            '"${CI_PROJECT_DIR}/registry/'
            'scan-registry.json"'
        ),
        (
            "      --expected-registry-sha256 "
            + registry_sha256
        ),
        (
            "      --expected-bridge-sha256 "
            + shlex.quote(configuration.bridge_sha256)
        ),
        (
            "      --mode "
            '"${WINTERMUTE_SCAN_MODE}"'
        ),
        (
            "      --confirmation "
            '"${WINTERMUTE_SCAN_CONFIRMATION}"'
        ),
        (
            "      --receipt-root "
            '"${CI_PROJECT_DIR}/.wintermute/'
            'scan/receipts"'
        ),
    ]

    if configuration.gitlab_insecure:
        lines.append(
            "      --insecure"
        )

    lines.extend(
        [
            "  artifacts:",
            "    when: always",
            "    expire_in: 30 days",
            "    paths:",
            (
                "      - .wintermute/"
                "scan/receipts/"
            ),
            "  rules:",
            (
                "    - if: '$TARGET_PROJECT_ID "
                "=~ /^[0-9]+$/ && "
                "$TARGET_COMMIT_SHA =~ "
                "/^[0-9a-f]{40}"
                "([0-9a-f]{24})?$/'"
            ),
            "      when: on_success",
            "    - when: never",
            "",
        ]
    )

    return "\n".join(lines)


def render_bundle(
    template_plan: LoadedTemplatePlan,
    configuration: CentralBundleConfiguration,
) -> tuple[
    dict[str, Any],
    str | None,
    str | None,
]:
    configuration.validate()
    registry = runtime_registry(
        template_plan
    )
    providers = {
        value["provider"]
        for value in registry["assignments"]
    }
    digest = hashlib.sha256(
        registry_bytes(registry)
    ).hexdigest()
    github = None
    gitlab = None

    if "github" in providers:
        if not configuration.github_repository:
            raise ValueError(
                "GitHub assignments require "
                "a central GitHub repository"
            )

        github = render_github_workflow(
            configuration,
            digest,
        )

    if "gitlab" in providers:
        if not configuration.gitlab_project:
            raise ValueError(
                "GitLab assignments require "
                "a central GitLab project"
            )

        gitlab = render_gitlab_template(
            configuration,
            digest,
        )

    return registry, github, gitlab


def write_bundle(
    root: str | Path,
    template_plan: LoadedTemplatePlan,
    configuration: CentralBundleConfiguration,
) -> Path:
    registry, github, gitlab = (
        render_bundle(
            template_plan,
            configuration,
        )
    )
    registry_sha256 = hashlib.sha256(
        registry_bytes(registry)
    ).hexdigest()
    launcher = (
        render_gitlab_launcher(
            configuration,
            registry_sha256,
        )
        if gitlab is not None
        else None
    )
    fingerprint = stable_digest(
        {
            "renderer_version": (
                BUNDLE_RENDERER_VERSION
            ),
            "template_plan_digest": (
                template_plan.digest
            ),
            "configuration": (
                asdict(configuration)
            ),
            "registry": registry,
            "github_workflow": github,
            "gitlab_template": gitlab,
            "gitlab_launcher": launcher,
        }
    )
    identifier = bundle_id(
        fingerprint
    )
    root_path = Path(root)
    staging = (
        root_path / ".staging" / identifier
    )
    destination = root_path / identifier

    if destination.is_dir():
        return destination

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )
    names = [
        "registry/scan-registry.json",
        "wintermute-managed.json",
    ]

    try:
        registry_path = (
            staging
            / "registry"
            / "scan-registry.json"
        )
        registry_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        registry_path.write_bytes(
            registry_bytes(registry)
        )

        if github is not None:
            path = (
                staging
                / ".github"
                / "workflows"
                / "wintermute-security.yml"
            )
            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            path.write_text(
                github,
                encoding="utf-8",
            )
            names.append(
                ".github/workflows/"
                "wintermute-security.yml"
            )

        if gitlab is not None:
            template_path = (
                staging
                / "templates"
                / "wintermute-security.yml"
            )
            template_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            template_path.write_text(
                gitlab,
                encoding="utf-8",
            )
            names.append(
                "templates/"
                "wintermute-security.yml"
            )
            launcher_path = (
                staging / ".gitlab-ci.yml"
            )
            launcher_path.write_text(
                str(launcher),
                encoding="utf-8",
            )
            names.append(
                ".gitlab-ci.yml"
            )

        created_at = str(
            template_plan.plan.get(
                "created_at"
            )
            or now_text()
        )
        managed = {
            "schema_version": 1,
            "bundle_id": identifier,
            "created_at": created_at,
            "renderer_version": (
                BUNDLE_RENDERER_VERSION
            ),
            "management_mode": (
                "initialize-only"
            ),
            "source_template_plan_id": (
                template_plan.plan[
                    "plan_id"
                ]
            ),
            "source_template_plan_digest": (
                template_plan.digest
            ),
            "registry_sha256": (
                registry_sha256
            ),
            "managed_files": sorted(names),
        }
        atomic_write_json(
            staging
            / "wintermute-managed.json",
            managed,
        )
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    name: sha256_file(
                        staging / name
                    )
                    for name in names
                },
            },
        )
        os.replace(
            staging,
            destination,
        )
        atomic_write_json(
            destination / "READY",
            {
                "schema_version": 1,
                "bundle_id": identifier,
                "ready_at": now_text(),
            },
        )

        return destination

    except BaseException:
        shutil.rmtree(
            staging,
            ignore_errors=True,
        )
        raise
