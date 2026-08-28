#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from wintermute.blackduck.actions.artifacts import (
    load_verified_action_plan,
)
from wintermute.blackduck.actions.results import (
    load_verified_execution_result,
)


TARGET_VARIABLES = (
    "WINTERMUTE_CIP_PROJECT_VERSION_HREF",
    "WINTERMUTE_CIP_COMPONENT_VERSION_HREF",
    "WINTERMUTE_CIP_TAG",
    "WINTERMUTE_CIP_BRANCH",
)

SUCCESSFUL_DRY_RUN_OUTCOMES = {
    "planned",
    "already-satisfied",
}


class SmokeError(RuntimeError):
    pass


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def output_root(root: Path) -> Path:
    configured = os.getenv(
        "WINTERMUTE_OUTPUT_DIR",
        "",
    ).strip()

    if configured:
        path = Path(configured).expanduser()
        return (
            path
            if path.is_absolute()
            else root / path
        )

    return root / ".wintermute"


def atomic_write_json(
    path: Path,
    payload: Any,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    temporary = path.with_name(
        f"{path.name}.{uuid.uuid4().hex}.tmp"
    )

    try:
        temporary.write_text(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        os.replace(
            temporary,
            path,
        )
    finally:
        temporary.unlink(missing_ok=True)


def decode_output(
    value: str | bytes | None,
) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace",
        )

    return value


def remaining_seconds(
    deadline: float,
) -> float:
    remaining = (
        deadline - time.monotonic()
    )

    if remaining <= 0:
        raise SmokeError(
            "Endpoint smoke runtime was exhausted"
        )

    return remaining


def run_command(
    name: str,
    command: list[str],
    *,
    root: Path,
    environment: dict[str, str],
    run_directory: Path,
    deadline: float,
) -> subprocess.CompletedProcess[str]:
    stdout_path = (
        run_directory / f"{name}.stdout.log"
    )
    stderr_path = (
        run_directory / f"{name}.stderr.log"
    )

    try:
        completed = subprocess.run(
            command,
            cwd=str(root),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=remaining_seconds(deadline),
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout_path.write_text(
            decode_output(error.stdout),
            encoding="utf-8",
        )
        stderr_path.write_text(
            decode_output(error.stderr),
            encoding="utf-8",
        )
        raise SmokeError(
            f"{name} timed out; see "
            f"{stderr_path}"
        ) from error

    stdout_path.write_text(
        completed.stdout or "",
        encoding="utf-8",
    )
    stderr_path.write_text(
        completed.stderr or "",
        encoding="utf-8",
    )

    if completed.returncode != 0:
        raise SmokeError(
            f"{name} exited with code "
            f"{completed.returncode}; see "
            f"{stderr_path}"
        )

    return completed


def required_environment() -> dict[str, str]:
    environment = dict(os.environ)
    missing = [
        name
        for name in (
            "BLACKDUCK_URL",
            "BLACKDUCK_API_TOKEN",
        )
        if not environment.get(
            name,
            "",
        ).strip()
    ]

    if missing:
        raise SmokeError(
            "Missing environment variable(s): "
            + ", ".join(missing)
        )

    return environment


def parse_environment_file(
    path: Path,
) -> dict[str, str]:
    if not path.is_file():
        return {}

    values: dict[str, str] = {}

    for number, raw_line in enumerate(
        path.read_text(
            encoding="utf-8"
        ).splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line:
            continue

        if "=" not in line:
            raise SmokeError(
                f"Invalid target environment line "
                f"{number}"
            )

        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()

        if name not in TARGET_VARIABLES:
            raise SmokeError(
                f"Unsupported target environment "
                f"variable: {name}"
            )

        if not value:
            raise SmokeError(
                f"Target environment variable "
                f"{name} is empty"
            )

        if "\r" in value or "\n" in value:
            raise SmokeError(
                f"Target environment variable "
                f"{name} is invalid"
            )

        values[name] = value

    return values


def target_is_complete(
    environment: dict[str, str],
) -> bool:
    return all(
        environment.get(
            name,
            "",
        ).strip()
        for name in TARGET_VARIABLES
    )


def tls_arguments(
    args: argparse.Namespace,
) -> list[str]:
    if args.insecure:
        return ["--insecure"]

    if args.ca_bundle:
        return [
            "--ca-bundle",
            args.ca_bundle,
        ]

    return []


def discover_target(
    args: argparse.Namespace,
    *,
    root: Path,
    environment: dict[str, str],
    run_directory: Path,
    target_environment_path: Path,
    deadline: float,
) -> None:
    discovery_output = (
        run_directory / "discovery.json"
    )
    command = [
        sys.executable,
        "-m",
        (
            "wintermute.blackduck.jobs."
            "cip.discover"
        ),
        "--output",
        str(discovery_output),
        "--environment-out",
        str(target_environment_path),
        "--max-projects",
        str(args.max_projects),
        "--max-versions-per-project",
        str(
            args.max_versions_per_project
        ),
        "--max-project-versions",
        str(args.max_project_versions),
        "--workers",
        str(args.discovery_workers),
        *tls_arguments(args),
    ]

    run_command(
        "discovery",
        command,
        root=root,
        environment=environment,
        run_directory=run_directory,
        deadline=deadline,
    )


def load_target_environment(
    args: argparse.Namespace,
    *,
    root: Path,
    environment: dict[str, str],
    run_directory: Path,
    target_environment_path: Path,
    deadline: float,
) -> dict[str, str]:
    if args.refresh_discovery:
        discover_target(
            args,
            root=root,
            environment=environment,
            run_directory=run_directory,
            target_environment_path=(
                target_environment_path
            ),
            deadline=deadline,
        )

        environment.update(
            parse_environment_file(
                target_environment_path
            )
        )
    else:
        file_values = parse_environment_file(
            target_environment_path
        )

        for name, value in file_values.items():
            environment.setdefault(
                name,
                value,
            )

        if not target_is_complete(
            environment
        ):
            discover_target(
                args,
                root=root,
                environment=environment,
                run_directory=run_directory,
                target_environment_path=(
                    target_environment_path
                ),
                deadline=deadline,
            )
            environment.update(
                parse_environment_file(
                    target_environment_path
                )
            )

    if not target_is_complete(
        environment
    ):
        missing = [
            name
            for name in TARGET_VARIABLES
            if not environment.get(
                name,
                "",
            ).strip()
        ]
        raise SmokeError(
            "Target discovery did not provide: "
            + ", ".join(missing)
        )

    return environment


def validate_probe(
    path: Path,
) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise SmokeError(
            f"Could not read probe output: "
            f"{error}"
        ) from error

    if not isinstance(payload, dict):
        raise SmokeError(
            "Probe output is not an object"
        )

    if int(
        payload.get("failure_count") or 0
    ) != 0:
        raise SmokeError(
            "Probe reported failures"
        )

    targets = payload.get("targets")

    if (
        not isinstance(targets, list)
        or not targets
    ):
        raise SmokeError(
            "Probe reported no targets"
        )

    readable = False

    for target in targets:
        if not isinstance(target, dict):
            continue

        if target.get("status") != "succeeded":
            raise SmokeError(
                "Probe target did not succeed"
            )

        occurrences = target.get(
            "occurrences",
            [],
        )

        if not isinstance(occurrences, list):
            continue

        readable = readable or any(
            isinstance(occurrence, dict)
            and isinstance(
                occurrence.get(
                    "remediation"
                ),
                dict,
            )
            and occurrence[
                "remediation"
            ].get("status")
            not in (None, "")
            for occurrence in occurrences
        )

    if not readable:
        raise SmokeError(
            "Probe found no readable project-scoped "
            "remediation resource"
        )

    return payload


def parse_json_stdout(
    completed: subprocess.CompletedProcess[str],
    *,
    name: str,
) -> dict[str, Any]:
    try:
        payload = json.loads(
            completed.stdout
        )
    except json.JSONDecodeError as error:
        raise SmokeError(
            f"{name} did not return JSON"
        ) from error

    if not isinstance(payload, dict):
        raise SmokeError(
            f"{name} output is not an object"
        )

    return payload


def validate_job(
    payload: dict[str, Any],
    *,
    require_actions: bool,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:
    if payload.get("mode") != "dry-run":
        raise SmokeError(
            "CIP job did not run in dry-run mode"
        )

    if payload.get("status") != "ok":
        raise SmokeError(
            "CIP job did not complete successfully"
        )

    planning = payload.get("plan")
    execution = payload.get("execution")

    if not isinstance(planning, dict):
        raise SmokeError(
            "CIP job has no plan summary"
        )

    if not isinstance(execution, dict):
        raise SmokeError(
            "CIP job has no execution summary"
        )

    if int(
        planning.get("failure_count") or 0
    ) != 0:
        raise SmokeError(
            "CIP planning reported failures"
        )

    if int(
        planning.get("candidate_count") or 0
    ) < 1:
        raise SmokeError(
            "CIP planning found no candidates"
        )

    if int(
        planning.get("assessment_count") or 0
    ) < 1:
        raise SmokeError(
            "CIP planning made no assessments"
        )

    action_count = int(
        planning.get("action_count") or 0
    )

    if require_actions and action_count < 1:
        raise SmokeError(
            "CIP planning produced no actions"
        )

    if execution.get("status") != "ok":
        raise SmokeError(
            "Action dry run did not succeed"
        )

    if int(execution.get("writes") or 0) != 0:
        raise SmokeError(
            "Endpoint smoke unexpectedly wrote "
            "to Black Duck"
        )

    receipts = execution.get("receipts")

    if not isinstance(receipts, list):
        raise SmokeError(
            "Action dry run has no receipts"
        )

    unexpected = {
        str(receipt.get("outcome") or "")
        for receipt in receipts
        if (
            isinstance(receipt, dict)
            and receipt.get("outcome")
            not in SUCCESSFUL_DRY_RUN_OUTCOMES
        )
    }

    if unexpected:
        raise SmokeError(
            "Action dry run returned unexpected "
            "outcome(s): "
            + ", ".join(sorted(unexpected))
        )

    if len(receipts) != action_count:
        raise SmokeError(
            "Action receipt count does not match "
            "the plan"
        )

    return planning, execution


def verify_artifacts(
    planning: dict[str, Any],
    payload: dict[str, Any],
) -> tuple[str, str]:
    plan_path = Path(
        str(planning.get("path") or "")
    )
    result_path = Path(
        str(payload.get("result_path") or "")
    )

    if not plan_path.is_dir():
        raise SmokeError(
            "Generated action-plan directory "
            "does not exist"
        )

    if not result_path.is_dir():
        raise SmokeError(
            "Generated action-result directory "
            "does not exist"
        )

    plan = load_verified_action_plan(
        plan_path
    )
    result = (
        load_verified_execution_result(
            result_path
        )
    )

    if (
        plan.plan_id
        != planning.get("plan_id")
    ):
        raise SmokeError(
            "Verified plan ID does not match "
            "the job output"
        )

    if (
        plan.digest
        != planning.get("plan_digest")
    ):
        raise SmokeError(
            "Verified plan digest does not match "
            "the job output"
        )

    if result.plan_id != plan.plan_id:
        raise SmokeError(
            "Verified result references another plan"
        )

    if result.plan_digest != plan.digest:
        raise SmokeError(
            "Verified result digest does not match "
            "the plan"
        )

    if result.writes != 0:
        raise SmokeError(
            "Verified result contains writes"
        )

    return str(plan_path), str(result_path)


def run(
    args: argparse.Namespace,
) -> int:
    root = project_root()
    runtime_root = output_root(root)
    run_id = (
        time.strftime(
            "%Y%m%dT%H%M%SZ",
            time.gmtime(),
        )
        + "-"
        + uuid.uuid4().hex[:8]
    )
    run_directory = (
        runtime_root
        / "blackduck"
        / "jobs"
        / "cip"
        / "smoke"
        / run_id
    )
    run_directory.mkdir(
        parents=True,
        exist_ok=False,
    )
    deadline = (
        time.monotonic()
        + args.max_seconds
    )
    environment = required_environment()
    environment[
        "WINTERMUTE_OUTPUT_DIR"
    ] = str(runtime_root)
    configuration_path = Path(
        args.config
    ).expanduser()

    if not configuration_path.is_absolute():
        configuration_path = (
            root / configuration_path
        )

    if not configuration_path.is_file():
        raise SmokeError(
            "CIP configuration does not exist: "
            f"{configuration_path}"
        )

    environment[
        "CIP_REMEDIATION_CONFIG"
    ] = str(configuration_path)
    target_environment_path = Path(
        args.target_environment
    ).expanduser()

    if not target_environment_path.is_absolute():
        target_environment_path = (
            root / target_environment_path
        )

    environment = load_target_environment(
        args,
        root=root,
        environment=environment,
        run_directory=run_directory,
        target_environment_path=(
            target_environment_path
        ),
        deadline=deadline,
    )
    probe_path = (
        run_directory / "probe.json"
    )
    probe_command = [
        sys.executable,
        "-m",
        (
            "wintermute.blackduck.actions."
            "probe"
        ),
        "--config",
        str(configuration_path),
        "--output",
        str(probe_path),
        "--component-page-size",
        str(args.component_page_size),
        "--max-component-pages",
        str(args.max_component_pages),
        "--max-vulnerabilities",
        str(args.max_vulnerabilities),
        "--max-remediations",
        "1",
        *tls_arguments(args),
    ]
    run_command(
        "probe",
        probe_command,
        root=root,
        environment=environment,
        run_directory=run_directory,
        deadline=deadline,
    )
    probe = validate_probe(probe_path)
    job_root = run_directory / "job"
    job_command = [
        sys.executable,
        "-m",
        (
            "wintermute.blackduck.jobs."
            "cip.job"
        ),
        "--dry-run",
        "--config",
        str(configuration_path),
        "--plan-root",
        str(job_root / "plans"),
        "--result-root",
        str(job_root / "results"),
        "--cache-root",
        str(job_root / "cache"),
        "--lock",
        str(job_root / "job.lock"),
        "--refresh-target-cursors",
        "--target-page-size",
        str(args.target_page_size),
        "--max-occurrences-per-target",
        str(
            args.max_occurrences_per_target
        ),
        "--max-candidates-per-run",
        str(args.max_candidates),
        "--max-actions",
        str(args.max_candidates),
        "--max-reads",
        str(args.max_blackduck_requests),
        "--max-writes",
        "0",
        "--max-blackduck-requests",
        str(args.max_blackduck_requests),
        "--max-gitlab-requests",
        str(args.max_gitlab_requests),
        "--progress-every",
        str(args.progress_every),
        "--max-hours",
        str(
            max(
                0.1,
                args.max_seconds / 3600,
            )
        ),
        *tls_arguments(args),
    ]
    completed = run_command(
        "cip-job",
        job_command,
        root=root,
        environment=environment,
        run_directory=run_directory,
        deadline=deadline,
    )
    job_payload = parse_json_stdout(
        completed,
        name="CIP job",
    )
    planning, execution = validate_job(
        job_payload,
        require_actions=(
            not args.allow_no_actions
        ),
    )
    plan_path, result_path = (
        verify_artifacts(
            planning,
            job_payload,
        )
    )
    summary = {
        "schema_version": 1,
        "run_id": run_id,
        "status": "succeeded",
        "mode": "dry-run",
        "writes": 0,
        "target_count": (
            probe.get("target_count")
        ),
        "candidate_count": (
            planning.get("candidate_count")
        ),
        "assessment_count": (
            planning.get(
                "assessment_count"
            )
        ),
        "action_count": (
            planning.get("action_count")
        ),
        "execution_counts": (
            execution.get("counts")
        ),
        "blackduck_requests": (
            job_payload.get(
                "blackduck_requests"
            )
        ),
        "gitlab_requests": (
            job_payload.get(
                "gitlab_requests"
            )
        ),
        "plan_path": plan_path,
        "result_path": result_path,
        "run_directory": str(run_directory),
    }
    summary_path = (
        run_directory / "summary.json"
    )
    atomic_write_json(
        summary_path,
        summary,
    )
    print(
        json.dumps(
            {
                **summary,
                "summary_path": (
                    str(summary_path)
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 0


def parse_args() -> argparse.Namespace:
    root = project_root()
    runtime_root = output_root(root)
    parser = argparse.ArgumentParser(
        description=(
            "Run the read-only CIP endpoint smoke "
            "test against Black Duck and GitLab."
        )
    )
    parser.add_argument(
        "--config",
        default=str(
            root
            / "src"
            / "wintermute"
            / "blackduck"
            / "jobs"
            / "cip"
            / "config"
            / "cip-remediation.json"
        ),
    )
    parser.add_argument(
        "--target-environment",
        default=str(
            runtime_root
            / "blackduck"
            / "jobs"
            / "cip"
            / "selected-target.env"
        ),
    )
    parser.add_argument(
        "--refresh-discovery",
        action="store_true",
    )
    parser.add_argument(
        "--allow-no-actions",
        action="store_true",
    )
    parser.add_argument(
        "--max-seconds",
        type=float,
        default=1800,
    )
    parser.add_argument(
        "--max-projects",
        type=int,
        default=50,
    )
    parser.add_argument(
        "--max-versions-per-project",
        type=int,
        default=5,
    )
    parser.add_argument(
        "--max-project-versions",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--discovery-workers",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--component-page-size",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--max-component-pages",
        type=int,
        default=50,
    )
    parser.add_argument(
        "--max-vulnerabilities",
        type=int,
        default=20,
    )
    parser.add_argument(
        "--target-page-size",
        type=int,
        default=25,
    )
    parser.add_argument(
        "--max-occurrences-per-target",
        type=int,
        default=25,
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--max-blackduck-requests",
        type=int,
        default=250,
    )
    parser.add_argument(
        "--max-gitlab-requests",
        type=int,
        default=250,
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=5,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument(
        "--ca-bundle",
    )

    args = parser.parse_args()

    if args.max_seconds <= 0:
        parser.error(
            "--max-seconds must be positive"
        )

    for name in (
        "max_projects",
        "max_versions_per_project",
        "max_project_versions",
        "discovery_workers",
        "component_page_size",
        "max_component_pages",
        "max_vulnerabilities",
        "target_page_size",
        "max_occurrences_per_target",
        "max_candidates",
        "max_blackduck_requests",
        "max_gitlab_requests",
        "progress_every",
    ):
        if int(getattr(args, name)) < 1:
            parser.error(
                f"--{name.replace('_', '-')} "
                "must be positive"
            )

    return args


def main() -> int:
    try:
        return run(parse_args())
    except KeyboardInterrupt:
        print(
            "Interrupted.",
            file=sys.stderr,
        )
        return 130
    except (
        OSError,
        SmokeError,
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
