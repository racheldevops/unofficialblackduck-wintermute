#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class PreMergeError(RuntimeError):
    pass


@dataclass(frozen=True)
class StepResult:
    name: str
    command: tuple[str, ...]
    return_code: int
    elapsed_seconds: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": list(self.command),
            "return_code": self.return_code,
            "elapsed_seconds": (
                self.elapsed_seconds
            ),
        }


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def runtime_root(
    root: Path,
) -> Path:
    configured = os.getenv(
        "WINTERMUTE_OUTPUT_DIR",
        "",
    ).strip()

    if not configured:
        return root / ".wintermute"

    path = Path(configured).expanduser()

    if path.is_absolute():
        return path

    return root / path


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


def require_environment(
    environment: dict[str, str],
    names: tuple[str, ...],
    *,
    step: str,
) -> None:
    missing = [
        name
        for name in names
        if not environment.get(
            name,
            "",
        ).strip()
    ]

    if missing:
        raise PreMergeError(
            f"{step} requires environment "
            "variable(s): "
            + ", ".join(missing)
        )


def safe_command(
    command: list[str],
) -> tuple[str, ...]:
    secret_flags = {
        "--api-token",
        "--action-api-token",
        "--gitlab-token",
    }
    result: list[str] = []
    redact_next = False

    for value in command:
        if redact_next:
            result.append("<redacted>")
            redact_next = False
            continue

        result.append(value)

        if value in secret_flags:
            redact_next = True

    return tuple(result)


def run_step(
    name: str,
    command: list[str],
    *,
    root: Path,
    environment: dict[str, str],
    timeout_seconds: float,
) -> StepResult:
    rendered = safe_command(command)
    started = time.monotonic()

    print()
    print("=" * 72)
    print(f"Pre-merge step: {name}")
    print("=" * 72)
    print(" ".join(rendered))
    sys.stdout.flush()

    try:
        completed = subprocess.run(
            command,
            cwd=str(root),
            env=environment,
            stdin=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise PreMergeError(
            f"{name} exceeded "
            f"{timeout_seconds:g} seconds"
        ) from error

    elapsed = round(
        time.monotonic() - started,
        3,
    )
    result = StepResult(
        name=name,
        command=rendered,
        return_code=completed.returncode,
        elapsed_seconds=elapsed,
    )

    if completed.returncode != 0:
        raise PreMergeError(
            f"{name} exited with code "
            f"{completed.returncode}"
        )

    print(
        f"Completed {name} in {elapsed:.3f}s"
    )
    return result


def local_steps(
    args: argparse.Namespace,
    *,
    root: Path,
    environment: dict[str, str],
) -> list[StepResult]:
    commands: list[
        tuple[str, list[str]]
    ] = [
        (
            "compile Python sources",
            [
                sys.executable,
                "-m",
                "compileall",
                "-q",
                "src",
                "scripts",
            ],
        ),
        (
            "full pytest suite",
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests",
            ],
        ),
        (
            "entrypoint validation",
            [
                sys.executable,
                "scripts/validate_entrypoints.py",
            ],
        ),
        (
            "release validation",
            [
                sys.executable,
                "scripts/validate_release.py",
                "--skip-docker",
            ],
        ),
    ]

    if args.require_installed_entrypoints:
        commands[2][1].append(
            "--require-installed"
        )

    return [
        run_step(
            name,
            command,
            root=root,
            environment=environment,
            timeout_seconds=(
                args.step_timeout
            ),
        )
        for name, command in commands
    ]


def scm_environment(
    environment: dict[str, str],
) -> dict[str, str]:
    selected = dict(environment)
    require_environment(
        selected,
        (
            "SCM_URL",
            "GITLAB_GROUP",
            "GITLAB_TOKEN",
            "BLACKDUCK_URL",
            "BLACKDUCK_API_TOKEN",
        ),
        step="live SCM smoke",
    )
    return selected


def cip_environment(
    environment: dict[str, str],
) -> dict[str, str]:
    selected = dict(environment)
    require_environment(
        selected,
        (
            "BLACKDUCK_URL",
            "BLACKDUCK_API_TOKEN",
        ),
        step="live CIP smoke",
    )

    selected.pop("SCM_URL", None)
    selected.pop("GITLAB_GROUP", None)
    selected["GITLAB_REST_URL"] = (
        environment.get(
            "CIP_GITLAB_REST_URL",
            "",
        ).strip()
        or "https://gitlab.com/api/v4"
    )
    cip_token = environment.get(
        "CIP_GITLAB_TOKEN",
        "",
    ).strip()

    if cip_token:
        selected["GITLAB_TOKEN"] = (
            cip_token
        )
    else:
        selected.pop("GITLAB_TOKEN", None)

    return selected


def live_scm_step(
    args: argparse.Namespace,
    *,
    root: Path,
    environment: dict[str, str],
) -> StepResult:
    command = [
        sys.executable,
        "scripts/run_scm_coverage_read_only.py",
        "--workers",
        "2",
        "--evidence-workers",
        "2",
        "--pipeline-limit",
        "3",
        "--scan-evidence-workers",
        "2",
        "--page-size",
        "100",
        "--page-limit",
        "100",
        "--collect-direct-scan-evidence",
        "--max-projects",
        "2",
        "--max-versions",
        "5",
        *tls_arguments(args),
    ]

    return run_step(
        "live GitLab and Black Duck SCM smoke",
        command,
        root=root,
        environment=scm_environment(
            environment
        ),
        timeout_seconds=(
            args.live_timeout
        ),
    )


def live_cip_step(
    args: argparse.Namespace,
    *,
    root: Path,
    environment: dict[str, str],
) -> StepResult:
    command = [
        sys.executable,
        "scripts/run_cip_endpoint_smoke.py",
        "--max-seconds",
        str(int(args.live_timeout)),
        "--target-page-size",
        "25",
        "--max-occurrences-per-target",
        "25",
        "--max-candidates",
        "10",
        "--max-blackduck-requests",
        "250",
        "--max-gitlab-requests",
        "250",
        "--progress-every",
        "5",
        *tls_arguments(args),
    ]

    return run_step(
        "live CIP zero-write endpoint smoke",
        command,
        root=root,
        environment=cip_environment(
            environment
        ),
        timeout_seconds=(
            args.live_timeout
        ),
    )


def run(
    args: argparse.Namespace,
) -> int:
    root = project_root()
    output = runtime_root(root)
    run_id = (
        time.strftime(
            "%Y%m%dT%H%M%SZ",
            time.gmtime(),
        )
        + "-"
        + uuid.uuid4().hex[:8]
    )
    summary_path = (
        output
        / "premerge"
        / run_id
        / "summary.json"
    )
    environment = dict(os.environ)
    environment[
        "WINTERMUTE_OUTPUT_DIR"
    ] = str(output)
    environment["PYTHONUNBUFFERED"] = "1"
    results: list[StepResult] = []
    started = time.monotonic()
    status = "running"
    error = ""

    try:
        results.extend(
            local_steps(
                args,
                root=root,
                environment=environment,
            )
        )

        if not args.skip_live_scm:
            results.append(
                live_scm_step(
                    args,
                    root=root,
                    environment=environment,
                )
            )

        if not args.skip_live_cip:
            results.append(
                live_cip_step(
                    args,
                    root=root,
                    environment=environment,
                )
            )

        status = "succeeded"
        return_code = 0

    except BaseException as caught:
        status = "failed"
        error = str(caught)
        return_code = 2

    summary = {
        "schema_version": 1,
        "run_id": run_id,
        "status": status,
        "error": error,
        "elapsed_seconds": round(
            time.monotonic() - started,
            3,
        ),
        "step_count": len(results),
        "steps": [
            result.as_dict()
            for result in results
        ],
    }
    atomic_write_json(
        summary_path,
        summary,
    )

    print()
    print("=" * 72)
    print("Pre-merge smoke summary")
    print("=" * 72)
    print(
        json.dumps(
            {
                **summary,
                "summary_path": str(
                    summary_path
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    if error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )

    return return_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run all local and read-only live "
            "pre-merge validation."
        )
    )
    parser.add_argument(
        "--skip-live-scm",
        action="store_true",
    )
    parser.add_argument(
        "--skip-live-cip",
        action="store_true",
    )
    parser.add_argument(
        "--require-installed-entrypoints",
        action="store_true",
    )
    parser.add_argument(
        "--step-timeout",
        type=float,
        default=1800,
    )
    parser.add_argument(
        "--live-timeout",
        type=float,
        default=3600,
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

    if args.step_timeout <= 0:
        parser.error(
            "--step-timeout must be positive"
        )

    if args.live_timeout <= 0:
        parser.error(
            "--live-timeout must be positive"
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


if __name__ == "__main__":
    raise SystemExit(main())
