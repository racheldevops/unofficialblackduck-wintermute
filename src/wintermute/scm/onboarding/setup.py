from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from wintermute.ai.models import stable_digest
from wintermute.scan.security import redact_payload, redact_text
from wintermute.scm.onboarding.central_bundle_job import inspect_bridge_platforms
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.file_lock import (
    FileLock,
    LockUnavailableError,
)
from wintermute.paths import output_root
from wintermute.scm.onboarding.bootstrap import (
    load_verified_central_bundle,
)
from wintermute.scm.onboarding.central_bundle import (
    CentralBundleConfiguration,
    write_bundle,
)
from wintermute.scm.onboarding.central_bundle_job import (
    INSPECT_DIGEST_PATTERN,
    inspect_bridge,
    inspect_image,
    run_command,
)
from wintermute.scm.onboarding.central_upgrade import (
    GitLabCentralUpgradeClient,
    build_upgrade_plan,
    execute_upgrade_plan,
    load_verified_upgrade_plan,
    write_upgrade_plan,
)
from wintermute.scm.onboarding.central_variables import (
    GitLabCentralVariablesClient,
    blackduck_variables,
    build_variables_plan,
    execute_variables_plan,
    load_variables_plan,
    write_variables_plan,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)
from wintermute.scm.onboarding.project_access import (
    GitLabProjectAccessClient,
    build_project_access_plan,
    execute_plan as execute_project_access,
    load_plan as load_project_access_plan,
    write_plan as write_project_access_plan,
)
from wintermute.scm.onboarding.template_artifacts import (
    load_verified_template_plan,
)
from wintermute.scm.providers.detection import (
    gitlab_rest_url,
)


CONFIRMATION = "SETUP_CENTRAL_SCANS"
IMAGE_DIGEST_PREFIX = "sha256:"


class SetupError(RuntimeError):
    pass


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def setup_id() -> str:
    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-central-scan-setup-"
        + uuid.uuid4().hex[:12]
    )


def project_root() -> Path:
    return Path.cwd().resolve()


def resolved_path(
    root: Path,
    value: str,
) -> Path:
    selected = Path(
        str(value or "")
    ).expanduser()

    return (
        selected.resolve()
        if selected.is_absolute()
        else (root / selected).resolve()
    )


def required_text(
    value: Any,
    field: str,
) -> str:
    selected = str(value or "").strip()

    if not selected:
        raise SetupError(
            f"{field} must not be empty"
        )

    return selected


def valid_digest(
    value: str,
) -> bool:
    selected = str(value or "").casefold()

    return (
        selected.startswith(
            IMAGE_DIGEST_PREFIX
        )
        and len(selected) == 71
        and all(
            character
            in "0123456789abcdef"
            for character
            in selected.removeprefix(
                IMAGE_DIGEST_PREFIX
            )
        )
    )


def read_object(
    path: Path,
) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise SetupError(
            f"Could not read {path}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise SetupError(
            f"Configuration is not an object: {path}"
        )

    return payload


def load_configuration(
    path: str,
) -> tuple[
    Path,
    dict[str, Any],
    str,
]:
    source = Path(path).expanduser().resolve()
    payload = read_object(source)

    if payload.get("schema_version") != 1:
        raise SetupError(
            "Unsupported setup configuration "
            "schema version"
        )

    return (
        source,
        payload,
        stable_digest(payload),
    )


def gitlab_configuration(
    configuration: dict[str, Any],
) -> dict[str, Any]:
    value = configuration.get("gitlab")

    if not isinstance(value, dict):
        raise SetupError(
            "gitlab configuration is required"
        )

    central_project = required_text(
        value.get("central_project"),
        "gitlab.central_project",
    ).strip("/")
    image_project = required_text(
        value.get("image_project"),
        "gitlab.image_project",
    ).strip("/")
    url = required_text(
        value.get("url"),
        "gitlab.url",
    )
    branch = str(
        value.get("central_branch")
        or "main"
    ).strip()

    for field, selected in (
        (
            "gitlab.central_project",
            central_project,
        ),
        (
            "gitlab.image_project",
            image_project,
        ),
    ):
        if selected.count("/") < 1:
            raise SetupError(
                f"{field} must use namespace/project"
            )

    if not branch:
        raise SetupError(
            "gitlab.central_branch must not be empty"
        )

    return {
        "url": url,
        "rest_url": gitlab_rest_url(url),
        "central_project": central_project,
        "central_branch": branch,
        "image_project": image_project,
    }


def target_projects(
    configuration: dict[str, Any],
) -> tuple[str, ...]:
    values = configuration.get(
        "target_projects"
    )

    if (
        not isinstance(values, list)
        or not values
        or not all(
            isinstance(value, str)
            and value.strip("/")
            .count("/") >= 1
            for value in values
        )
    ):
        raise SetupError(
            "target_projects must contain exact "
            "GitLab namespace/project paths"
        )

    return tuple(
        sorted(
            {
                value.strip("/")
                for value in values
            }
        )
    )


def tls_options(
    configuration: dict[str, Any],
) -> dict[str, Any]:
    value = configuration.get(
        "tls",
        {},
    )

    if not isinstance(value, dict):
        raise SetupError(
            "tls configuration must be an object"
        )

    insecure = value.get(
        "insecure",
        False,
    )
    ca_bundle = str(
        value.get("ca_bundle")
        or ""
    ).strip()

    if type(insecure) is not bool:
        raise SetupError(
            "tls.insecure must be boolean"
        )

    if insecure and ca_bundle:
        raise SetupError(
            "Use tls.insecure or tls.ca_bundle, "
            "not both"
        )

    return {
        "insecure": insecure,
        "ca_bundle": (
            ca_bundle or None
        ),
    }


def transport_options(
    configuration: dict[str, Any],
) -> dict[str, Any]:
    value = configuration.get(
        "transport",
        {},
    )

    if not isinstance(value, dict):
        raise SetupError(
            "transport configuration must "
            "be an object"
        )

    try:
        timeout = float(
            value.get(
                "timeout_seconds",
                30,
            )
        )
        retries = int(
            value.get("retries", 2)
        )
        retry_delay = float(
            value.get(
                "retry_delay_seconds",
                1,
            )
        )
        interval = float(
            value.get(
                "request_interval_seconds",
                0.5,
            )
        )
    except (
        TypeError,
        ValueError,
    ) as error:
        raise SetupError(
            "transport configuration contains "
            "a nonnumeric value"
        ) from error

    if timeout <= 0:
        raise SetupError(
            "transport timeout must be positive"
        )

    if retries < 0:
        raise SetupError(
            "transport retries cannot be negative"
        )

    if retry_delay < 0 or interval < 0:
        raise SetupError(
            "transport delays cannot be negative"
        )

    return {
        "timeout": timeout,
        "retries": retries,
        "retry_delay": retry_delay,
        "request_interval_seconds": interval,
    }


def token(
    name: str,
) -> str:
    value = os.getenv(
        name,
        "",
    ).strip()

    if not value:
        raise SetupError(
            f"{name} must be set"
        )

    return value


def action_token() -> str:
    from wintermute.scm.onboarding.credentials import gitlab_action_token

    return gitlab_action_token()



def api_client(
    client_type: type,
    *,
    gitlab: dict[str, Any],
    tls: dict[str, Any],
    transport: dict[str, Any],
    write_access: bool,
):
    selected_token = (
        action_token()
        if write_access
        else token("GITLAB_TOKEN")
    )

    return client_type(
        "gitlab",
        gitlab["rest_url"],
        selected_token,
        timeout=transport["timeout"],
        retries=transport["retries"],
        retry_delay=(
            transport["retry_delay"]
        ),
        request_interval_seconds=(
            transport[
                "request_interval_seconds"
            ]
        ),
        insecure=tls["insecure"],
        ca_bundle=tls["ca_bundle"],
    )


def strip_image_tag(
    value: str,
) -> str:
    selected = str(value or "").strip()

    if "@" in selected:
        return selected.split("@", 1)[0]

    slash = selected.rfind("/")
    colon = selected.rfind(":")

    if colon <= slash:
        raise SetupError(
            "Scan image tag is missing"
        )

    return selected[:colon]


def image_reference_from_tag(
    docker: str,
    tag: str,
    *,
    timeout: float,
) -> str:
    completed = run_command(
        [
            docker,
            "buildx",
            "imagetools",
            "inspect",
            tag,
        ],
        timeout=timeout,
    )
    match = INSPECT_DIGEST_PATTERN.search(
        completed.stdout
    )

    if match is None:
        raise SetupError(
            "Published scan image did not report "
            "an index digest"
        )

    digest = match.group(1).casefold()

    if not valid_digest(digest):
        raise SetupError(
            "Published scan image digest is invalid"
        )

    return (
        f"{strip_image_tag(tag)}@{digest}"
    )


def bridge_pins(
    root: Path,
    image: dict[str, Any],
) -> dict[str, str]:
    path = resolved_path(
        root,
        required_text(
            image.get("bridge_pins"),
            "scan_image.bridge_pins",
        ),
    )
    payload = read_object(path)
    values: dict[str, str] = {}

    for architecture in (
        "amd64",
        "arm64",
    ):
        item = payload.get(architecture)

        if not isinstance(item, dict):
            raise SetupError(
                "Bridge pin file is missing "
                f"{architecture}"
            )

        url = required_text(
            item.get("url"),
            f"{architecture} Bridge URL",
        )
        digest = str(
            item.get("sha256")
            or ""
        ).casefold()

        if not valid_digest(
            f"sha256:{digest}"
        ):
            raise SetupError(
                f"{architecture} Bridge digest "
                "is invalid"
            )

        values[
            f"{architecture}_url"
        ] = url
        values[
            f"{architecture}_sha256"
        ] = digest

    return values


def launcher_available(
    docker: str,
    image: str,
    *,
    timeout: float,
) -> bool:
    from wintermute.scan.security import redact_text

    try:
        run_command(
            [
                docker,
                "run",
                "--rm",
                "--entrypoint",
                "python",
                image,
                "-I",
                "-m",
                "wintermute.scan.launcher",
                "--help",
            ],
            timeout=timeout,
        )
    except (OSError, RuntimeError, ValueError) as error:
        raise SetupError(
            f"Launcher probe failed for {image}: "
            f"{redact_text(str(error))}"
        ) from error

    return True



def publish_scan_image(
    root: Path,
    value: dict[str, Any],
    *,
    docker: str,
    tag: str,
    timeout: float,
    work_directory: Path,
) -> str:
    if not tag or tag.endswith(
        ":latest"
    ):
        raise SetupError(
            "scan_image.tag must be an "
            "immutable non-latest tag"
        )

    pins = bridge_pins(
        root,
        value,
    )
    bridge_insecure = value.get(
        "bridge_bundle_insecure",
        False,
    )

    if type(bridge_insecure) is not bool:
        raise SetupError(
            "scan_image.bridge_bundle_insecure "
            "must be boolean"
        )

    command = [
        docker,
        "buildx",
        "build",
        "--platform",
        "linux/amd64,linux/arm64",
        "--target",
        "scan",
        "--build-arg",
        (
            "BRIDGE_BUNDLE_AMD64_URL="
            + pins["amd64_url"]
        ),
        "--build-arg",
        (
            "BRIDGE_BUNDLE_AMD64_SHA256="
            + pins["amd64_sha256"]
        ),
        "--build-arg",
        (
            "BRIDGE_BUNDLE_ARM64_URL="
            + pins["arm64_url"]
        ),
        "--build-arg",
        (
            "BRIDGE_BUNDLE_ARM64_SHA256="
            + pins["arm64_sha256"]
        ),
        "--build-arg",
        (
            "BRIDGE_BUNDLE_INSECURE="
            + str(bridge_insecure).lower()
        ),
        "--tag",
        tag,
        "--push",
        ".",
    ]
    log_path = (
        work_directory
        / "image-publish.log"
    )

    with log_path.open(
        "w",
        encoding="utf-8",
    ) as output_file:
        completed = subprocess.run(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=output_file,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )

    if completed.returncode != 0:
        raise SetupError(
            "Multi-architecture scan image "
            f"publish failed; see {log_path}"
        )

    return image_reference_from_tag(
        docker,
        tag,
        timeout=timeout,
    )


def resolve_scan_image(
    root: Path,
    configuration: dict[str, Any],
    *,
    work_directory: Path,
) -> tuple[str, dict[str, Any], dict[str, str], bool]:
    del root, work_directory
    value = configuration.get("scan_image")
    if not isinstance(value, dict):
        raise SetupError("scan_image configuration is required")

    docker = str(value.get("docker") or "docker")
    timeout = float(value.get("timeout_seconds", 1800))
    if not __import__("math").isfinite(timeout) or timeout <= 0:
        raise SetupError("scan_image timeout must be finite and positive")

    publish = value.get("publish_if_missing", False)
    if type(publish) is not bool:
        raise SetupError("scan_image.publish_if_missing must be boolean")

    configured_digest = str(value.get("digest_reference") or "").strip()
    tag = str(value.get("tag") or "").strip()

    if configured_digest:
        selected = configured_digest
    elif tag:
        selected = image_reference_from_tag(docker, tag, timeout=timeout)
    else:
        raise SetupError(
            "Provide scan_image.digest_reference or an existing scan_image.tag"
        )

    try:
        inspection = inspect_image(docker, selected, timeout=timeout)
        if not launcher_available(docker, selected, timeout=min(timeout, 300)):
            raise SetupError("The selected scan image has no usable launcher")
        checksums = inspect_bridge_platforms(
            docker,
            selected,
            timeout=min(timeout, 300),
        )
    except Exception as error:
        raise SetupError(
            "Scan image verification failed. Setup never publishes images; "
            "build/publish explicitly, then configure its verified digest. "
            f"Details: {redact_text(str(error))}"
        ) from error

    bridge = {
        "bridge_sha256": json.dumps(
            checksums,
            sort_keys=True,
            separators=(",", ":"),
        ),
    }
    return selected, inspection, bridge, False


def verified_template_plan(
    root: Path,
    configuration: dict[str, Any],
):
    reuse = configuration.get(
        "reuse"
    )

    if not isinstance(reuse, dict):
        raise SetupError(
            "reuse configuration is required"
        )

    path = resolved_path(
        root,
        required_text(
            reuse.get(
                "merged_template_plan"
            ),
            "reuse.merged_template_plan",
        ),
    )
    loaded = (
        load_verified_template_plan(path)
    )
    expected = required_text(
        reuse.get(
            "merged_template_plan_digest"
        ),
        (
            "reuse."
            "merged_template_plan_digest"
        ),
    )

    if loaded.digest != expected:
        raise SetupError(
            "Verified merged template-plan digest "
            "does not match the configuration"
        )

    expected_counts = configuration.get(
        "expected_counts",
        {},
    )

    if not isinstance(
        expected_counts,
        dict,
    ):
        raise SetupError(
            "expected_counts must be an object"
        )

    for field in (
        "repository_count",
        "required_count",
        "review_count",
        "scan_contract_count",
    ):
        expected_value = (
            expected_counts.get(field)
        )

        if (
            expected_value is not None
            and loaded.plan.get(field)
            != expected_value
        ):
            raise SetupError(
                f"Template-plan {field} mismatch"
            )

    return loaded


def central_exists(
    client: OnboardingHttpClient,
    project: str,
) -> bool:
    result = client.get_json(
        (
            f"/projects/"
            f"{quote(project, safe='')}"
        ),
        allow_not_found=True,
    )

    return result.status_code == 200


def write_setup_receipt(
    root: Path,
    identifier: str,
    payload: dict[str, Any],
) -> Path:
    staging = (
        root / ".staging" / identifier
    )
    destination = root / identifier

    if destination.exists():
        raise SetupError(
            "Setup receipt already exists"
        )

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        atomic_write_json(
            staging / "setup.json",
            redact_payload(payload),
        )
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    "setup.json": sha256_file(
                        staging / "setup.json"
                    ),
                },
            },
        )
        root.mkdir(
            parents=True,
            exist_ok=True,
        )
        os.replace(
            staging,
            destination,
        )
        atomic_write_json(
            destination / "READY",
            {
                "schema_version": 1,
                "setup_id": identifier,
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


def desired_blackduck_variables(
    configuration: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Build setup variables; retain the helper name for compatibility."""
    from wintermute.scm.onboarding.central_variables import launcher_variables

    enabled = configuration.get("provision_blackduck_variables", False)
    if type(enabled) is not bool:
        raise SetupError("provision_blackduck_variables must be boolean")

    desired = launcher_variables()
    if enabled:
        desired.update(blackduck_variables())

    return desired



def verify_approved_targets(
    template_plan,
    *,
    gitlab: dict[str, Any],
    targets: tuple[str, ...],
    access_plan: dict[str, Any] | None = None,
) -> None:
    from urllib.parse import urlsplit

    instance = urlsplit(gitlab["rest_url"]).netloc.casefold()
    assignments = template_plan.assignments["assignments"]
    approved = {}

    for target in targets:
        matches = [
            row
            for row in assignments
            if row.get("provider") == "gitlab"
            and str(row.get("provider_instance") or "").casefold() == instance
            and row.get("name_with_owner") == target
            and row.get("onboarding_policy") == "required"
            and row.get("scan_contract_id")
        ]
        if len(matches) != 1:
            raise SetupError(
                f"Target must have exactly one approved scan assignment: {target}"
            )
        approved[target] = str(matches[0]["repository_id"])

    if access_plan is not None:
        observed = {
            row["target_project"]: str(row["target_project_id"])
            for row in access_plan["observation"]["targets"]
        }
        for target, expected_id in approved.items():
            if observed.get(target) != expected_id:
                raise SetupError(
                    f"Target project identity differs from approved registry: {target}"
                )


def apply_tls_overrides(
    configuration: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    import copy

    selected = copy.deepcopy(configuration)
    insecure = getattr(args, "insecure", None)
    ca_bundle = getattr(args, "ca_bundle", None)

    if insecure not in (None, False, True):
        raise SetupError("--insecure must be boolean")
    if insecure is True and ca_bundle is not None:
        raise SetupError("Use --insecure or --ca-bundle, not both")

    if insecure is True:
        selected["tls"] = {"insecure": True, "ca_bundle": ""}
    elif ca_bundle is not None:
        if not isinstance(ca_bundle, str) or not ca_bundle.strip():
            raise SetupError("--ca-bundle must not be empty")
        selected["tls"] = {
            "insecure": False,
            "ca_bundle": str(Path(ca_bundle).expanduser().resolve()),
        }

    tls_options(selected)
    return selected


def run(args: argparse.Namespace) -> int:
    from functools import partial

    from wintermute.scan.security import redact_payload, redact_text
    from wintermute.scm.onboarding.setup_execution import (
        approval_digest,
        approval_payload,
        execute_phases,
    )

    if args.mode not in {"dry-run", "apply"}:
        raise SetupError("Setup mode is invalid")
    if type(args.max_writes) is not int or args.max_writes < 0:
        raise SetupError("Setup write budget must be a nonnegative integer")

    expected_setup_digest = str(
        getattr(args, "expected_setup_digest", "") or ""
    ).strip()

    if args.mode == "apply":
        if args.confirmation != CONFIRMATION:
            raise SetupError(
                f"Apply requires exact confirmation: {CONFIRMATION}"
            )
        if not valid_digest(expected_setup_digest):
            raise SetupError(
                "Apply requires --expected-setup-digest from a successful dry run"
            )
        action_token()

    root = project_root()
    identifier = setup_id()
    onboarding_root = output_root() / "scm" / "onboarding"
    receipt_root = onboarding_root / "setup-results"
    work_directory = receipt_root / ".work" / identifier
    work_directory.mkdir(parents=True, exist_ok=False)

    records: list[dict[str, Any]] = []
    phases: list[dict[str, Any]] = []
    accounting: dict[str, Any] = {
        "mutation_attempts": 0,
        "reported_successful_writes": 0,
        "verified_phase_writes": 0,
        "remote_write_outcome": "no-attempts",
    }
    config_path = Path(args.config).expanduser()
    config_digest = ""
    image = ""
    aggregate: dict[str, Any] | None = None
    aggregate_digest = ""
    desired_variables: dict[str, dict[str, Any]] = {}
    gitlab: dict[str, Any] = {}
    targets: tuple[str, ...] = ()
    template_plan = None
    bundle = None
    bridge: dict[str, str] = {}

    def prepare_phase(name, loaded, read_client, client_type, operation):
        record = {
            "phase": name + "-dry-run",
            "status": "started",
            "plan_id": loaded.plan["plan_id"],
            "plan_digest": loaded.digest,
            "plan_directory": str(loaded.directory),
        }
        records.append(record)
        before = read_client.writes
        try:
            code, result, directory = operation(
                read_client,
                mode="dry-run",
                maximum_writes=args.max_writes,
            )
            if read_client.writes != before:
                raise SetupError("A dry-run executor attempted a mutation")
            record.update({
                "status": result["status"],
                "outcome": result["outcome"],
                "estimated_writes": result["estimated_writes"],
                "result_directory": str(directory),
            })
            if code != 0 or result["status"] != "ok":
                raise SetupError(f"{name} dry run did not succeed")
        except BaseException as error:
            record["status"] = "failed"
            record["error"] = redact_text(str(error))
            raise

        phases.append({
            "name": name,
            "loaded": loaded,
            "client_type": client_type,
            "execute": operation,
        })

    try:
        config_path, configuration, config_digest = load_configuration(args.config)
        configuration = apply_tls_overrides(configuration, args)
        config_digest = stable_digest(configuration)
        gitlab = gitlab_configuration(configuration)
        targets = target_projects(configuration)
        tls = tls_options(configuration)
        transport = transport_options(configuration)
        desired_variables = desired_blackduck_variables(configuration)

        template_plan = verified_template_plan(root, configuration)
        verify_approved_targets(
            template_plan,
            gitlab=gitlab,
            targets=targets,
        )
        records.append({
            "phase": "verified-template-plan",
            "status": "succeeded",
            "plan_id": template_plan.plan["plan_id"],
            "plan_digest": template_plan.digest,
        })

        image, inspection, bridge, published = resolve_scan_image(
            root,
            configuration,
            work_directory=work_directory,
        )
        if published:
            raise SetupError("Setup must never publish images")
        records.append({
            "phase": "scan-image",
            "status": "succeeded",
            "image": image,
            "published": False,
            "platforms": inspection["platforms"],
            "bridge_sha256": bridge["bridge_sha256"],
        })

        bundle_directory = write_bundle(
            onboarding_root / "central-bundles",
            template_plan,
            CentralBundleConfiguration(
                image=image,
                bridge_sha256=bridge["bridge_sha256"],
                gitlab_project=gitlab["central_project"],
                gitlab_ref=gitlab["central_branch"],
                gitlab_insecure=tls["insecure"],
            ),
        )
        bundle = load_verified_central_bundle(bundle_directory)
        records.append({
            "phase": "central-bundle",
            "status": "succeeded",
            "bundle_id": bundle.bundle_id,
            "bundle_digest": bundle.digest,
            "bundle_directory": str(bundle.directory),
        })

        def read_client(client_type):
            return api_client(
                client_type,
                gitlab=gitlab,
                tls=tls,
                transport=transport,
                write_access=False,
            )

        upgrade_client = read_client(GitLabCentralUpgradeClient)
        upgrade_values = build_upgrade_plan(
            upgrade_client,
            bundle,
            project=gitlab["central_project"],
            branch=gitlab["central_branch"],
            expected_new_bundle_digest=bundle.digest,
        )
        upgrade_directory = write_upgrade_plan(
            onboarding_root / "central-upgrade-plans",
            *upgrade_values,
        )
        loaded_upgrade = load_verified_upgrade_plan(upgrade_directory)
        prepare_phase(
            "central-upgrade",
            loaded_upgrade,
            upgrade_client,
            GitLabCentralUpgradeClient,
            partial(
                execute_upgrade_plan,
                loaded_upgrade,
                result_root=onboarding_root / "central-upgrade-results",
            ),
        )

        if desired_variables:
            variable_client = read_client(GitLabCentralVariablesClient)
            variable_plan = build_variables_plan(
                variable_client,
                project=gitlab["central_project"],
                branch=gitlab["central_branch"],
                desired_variables=desired_variables,
            )
            variable_directory = write_variables_plan(
                onboarding_root / "central-variable-plans",
                variable_plan,
            )
            loaded_variables = load_variables_plan(variable_directory)
            prepare_phase(
                "central-variables",
                loaded_variables,
                variable_client,
                GitLabCentralVariablesClient,
                partial(
                    execute_variables_plan,
                    loaded_variables,
                    desired_variables=desired_variables,
                    result_root=onboarding_root / "central-variable-results",
                ),
            )

        access_client = read_client(GitLabProjectAccessClient)
        access_plan = build_project_access_plan(
            access_client,
            source_project=gitlab["central_project"],
            target_projects=tuple(sorted({
                *targets,
                gitlab["image_project"],
            })),
        )
        verify_approved_targets(
            template_plan,
            gitlab=gitlab,
            targets=targets,
            access_plan=access_plan,
        )
        access_directory = write_project_access_plan(
            onboarding_root / "project-access-plans",
            access_plan,
        )
        loaded_access = load_project_access_plan(access_directory)
        prepare_phase(
            "project-access",
            loaded_access,
            access_client,
            GitLabProjectAccessClient,
            partial(
                execute_project_access,
                loaded_access,
                result_root=onboarding_root / "project-access-results",
            ),
        )

        aggregate = approval_payload(
            configuration_digest=config_digest,
            template_plan_digest=template_plan.digest,
            bundle_digest=bundle.digest,
            image=image,
            phases=phases,
        )
        aggregate_digest = approval_digest(aggregate)

        if aggregate["estimated_writes"] > args.max_writes:
            raise SetupError(
                "Combined setup write budget exceeded: "
                f"{aggregate['estimated_writes']} planned, "
                f"{args.max_writes} allowed"
            )

        if args.mode == "apply":
            if aggregate_digest != expected_setup_digest:
                raise SetupError(
                    "Setup plan changed since approval; run dry-run and review "
                    "the new setup_plan_digest before applying"
                )

            # Construct every action client before the first remote write.
            for phase in phases:
                phase["client"] = api_client(
                    phase["client_type"],
                    gitlab=gitlab,
                    tls=tls,
                    transport=transport,
                    write_access=True,
                )

            execute_phases(
                phases,
                maximum_writes=args.max_writes,
                records=records,
                accounting=accounting,
            )

        receipt = {
            "schema_version": 2,
            "setup_id": identifier,
            "created_at": now_text(),
            "status": "succeeded",
            "outcome": "applied" if args.mode == "apply" else "planned",
            "mode": args.mode,
            "configuration_path": str(config_path),
            "configuration_digest": config_digest,
            "setup_plan_digest": aggregate_digest,
            "setup_plan": aggregate,
            "provider": "gitlab",
            "central_project": gitlab["central_project"],
            "target_projects": list(targets),
            "image_project": gitlab["image_project"],
            "scan_image": image,
            "template_plan_id": template_plan.plan["plan_id"],
            "template_plan_digest": template_plan.digest,
            "bundle_id": bundle.bundle_id,
            "bundle_digest": bundle.digest,
            "registry_sha256": bundle.managed["registry_sha256"],
            "bridge_sha256": bridge["bridge_sha256"],
            "launcher_scan_mode": "dry-run",
            "managed_ci_variables": sorted(desired_variables),
            "secret_values_recorded": False,
            "estimated_writes": aggregate["estimated_writes"],
            "writes": accounting["reported_successful_writes"],
            "write_accounting": accounting,
            "target_repository_modified": False,
            "phases": records,
        }
        directory = write_setup_receipt(receipt_root, identifier, receipt)

    except BaseException as error:
        failure = {
            "schema_version": 2,
            "setup_id": identifier,
            "created_at": now_text(),
            "status": (
                "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
            ),
            "mode": args.mode,
            "configuration_path": str(config_path),
            "configuration_digest": config_digest,
            "setup_plan_digest": aggregate_digest,
            "setup_plan": aggregate,
            "error": redact_text(str(error)),
            "scan_image": image,
            "managed_ci_variables": sorted(desired_variables),
            "estimated_writes": (
                aggregate["estimated_writes"] if aggregate is not None else 0
            ),
            "writes": accounting["reported_successful_writes"],
            "write_accounting": accounting,
            "phases": records,
        }
        directory = write_setup_receipt(receipt_root, identifier, failure)
        if isinstance(error, KeyboardInterrupt):
            raise
        if not isinstance(error, Exception):
            raise
        raise SetupError(
            f"{redact_text(str(error))}; failure receipt: {directory}"
        ) from error
    finally:
        shutil.rmtree(work_directory, ignore_errors=True)

    print(json.dumps(
        redact_payload({
            **receipt,
            "receipt_directory": str(directory),
        }),
        indent=2,
        sort_keys=True,
    ))
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    from wintermute.scm.onboarding.configuration_paths import (
        default_configuration_path,
        missing_configuration_message,
    )

    parser = argparse.ArgumentParser(
        description=(
            "Plan or apply central GitLab scan setup with aggregate approval, "
            "write-attempt budgets, and per-phase readback verification."
        )
    )
    parser.add_argument(
        "--config",
        default=default_configuration_path(),
        help=(
            "Configuration JSON path. Defaults to WINTERMUTE_ONBOARD_CONFIG "
            "or the module-local wintermute-onboard.local.json."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        dest="mode",
        action="store_const",
        const="dry-run",
    )
    mode.add_argument(
        "--apply",
        dest="mode",
        action="store_const",
        const="apply",
    )
    parser.set_defaults(mode="dry-run")
    parser.add_argument("--confirmation", default="")
    parser.add_argument(
        "--expected-setup-digest",
        default="",
        help="Apply requires setup_plan_digest from the reviewed dry-run receipt.",
    )
    parser.add_argument("--max-writes", type=int, default=8)
    parser.add_argument(
        "--lock",
        default=str(
            output_root() / "scm" / "onboarding" / "central-scan-setup.lock"
        ),
    )
    cli_tls = parser.add_mutually_exclusive_group()
    cli_tls.add_argument(
        "--insecure",
        action="store_true",
        default=None,
        help="Override configuration: disable GitLab TLS certificate verification.",
    )
    cli_tls.add_argument(
        "--ca-bundle",
        default=None,
        help="Override configuration: verify GitLab TLS using this PEM CA bundle.",
    )
    args = parser.parse_args(argv)

    if not args.config:
        parser.error(missing_configuration_message())

    if args.max_writes < 0:
        parser.error("--max-writes cannot be negative")
    if args.mode == "apply":
        if args.confirmation != CONFIRMATION:
            parser.error(
                f"Apply requires exact confirmation: {CONFIRMATION}"
            )
        if not valid_digest(args.expected_setup_digest):
            parser.error(
                "Apply requires --expected-setup-digest from a reviewed dry run"
            )
    return args


def main(
    argv: list[str] | None = None,
) -> int:
    secrets = [
        os.getenv("GITLAB_TOKEN", ""),
        os.getenv(
            "GITLAB_ACTION_TOKEN",
            "",
        ),
        os.getenv(
            "BLACKDUCK_API_TOKEN",
            "",
        ),
    ]

    try:
        args = parse_args(argv)
        token("GITLAB_TOKEN")
        if args.mode == "apply":
            action_token()

        with FileLock(
            args.lock,
            stale_seconds=7200,
            wait_seconds=0,
        ):
            return run(args)

    except KeyboardInterrupt:
        return 130
    except (
        LockUnavailableError,
        OSError,
        RuntimeError,
        SetupError,
        ValueError,
    ) as error:
        message = str(error)

        for secret in secrets:
            if secret:
                message = message.replace(
                    secret,
                    "[REDACTED]",
                )

        print(
            f"ERROR: {message}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
