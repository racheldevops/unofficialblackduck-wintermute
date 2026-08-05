#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import csv
import json
import os
import re
import resource
import signal
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STAGE_RE = re.compile(
    r"Pipeline stage completed:\s*(?P<name>.+?)\s+in\s+(?P<seconds>[0-9.]+)s"
)
SECRET_FLAGS = {
    "--api-token",
    "--password",
    "--token",
    "--jira-api-token",
    "--blackduck-api-token",
}
CSV_FIELDS = [
    "scenario",
    "workers",
    "iteration",
    "cache_state",
    "started_at",
    "elapsed_seconds",
    "return_code",
    "timed_out",
    "pod_elapsed_seconds",
    "pod_exit_code",
    "pod_restart_count",
    "launcher_user_seconds",
    "launcher_system_seconds",
    "stage_seconds",
    "metrics",
    "pipeline_summary",
    "command",
    "log_path",
    "error",
]


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def atomic_write_json(path: Path, payload: Any) -> None:
    atomic_write_text(
        path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )


def append_log(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", errors="replace") as output_file:
        output_file.write(text)
        if text and not text.endswith("\n"):
            output_file.write("\n")


def redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False

    for argument in command:
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue

        lowered = argument.lower()

        if argument in SECRET_FLAGS:
            redacted.append(argument)
            hide_next = True
            continue

        if any(
            marker in lowered
            for marker in (
                "api_token=",
                "api-token=",
                "password=",
                "authorization=",
            )
        ):
            key = argument.split("=", 1)[0]
            redacted.append(f"{key}=<redacted>")
            continue

        redacted.append(argument)

    return redacted


def run_capture(
    command: list[str],
    *,
    cwd: Path,
    input_text: str | None = None,
    timeout: float = 60,
) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout or ""
    except FileNotFoundError as error:
        return 127, str(error)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return 124, str(output)


def run_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    log_path: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    started = time.monotonic()
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    return_code = 127
    timed_out = False
    error = ""

    with log_path.open("wb") as output_file:
        try:
            process = subprocess.Popen(
                command,
                cwd=str(cwd),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

            try:
                return_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                return_code = 124

                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=10)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()

        except FileNotFoundError as caught:
            error = str(caught)
            output_file.write((error + "\n").encode("utf-8", errors="replace"))
        except OSError as caught:
            error = str(caught)
            output_file.write((error + "\n").encode("utf-8", errors="replace"))

    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)

    return {
        "started_at": started_at,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "return_code": return_code,
        "timed_out": timed_out,
        "launcher_user_seconds": round(
            usage_after.ru_utime - usage_before.ru_utime,
            3,
        ),
        "launcher_system_seconds": round(
            usage_after.ru_stime - usage_before.ru_stime,
            3,
        ),
        "command": redact_command(command),
        "log_path": str(log_path),
        "error": error,
    }


def parse_pipeline_log(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"stage_seconds": {}, "metrics": {}}

    text = path.read_text(encoding="utf-8", errors="replace")
    stage_seconds = {
        match.group("name").strip(): float(match.group("seconds"))
        for match in STAGE_RE.finditer(text)
    }

    metrics: dict[str, Any] = {
        "retry_lines": len(re.findall(r"(?m)^Retrying\b", text)),
        "http_429_lines": len(re.findall(r"\bHTTP 429\b", text)),
        "api_cache_hit_lines": len(
            re.findall(r"Reusing (?:in-run )?API cache", text)
        ),
    }

    patterns = {
        "indexed_project_versions": r"Indexed\s+(\d+)\s+project versions",
        "parent_cache_reused": r"Reusing\s+(\d+)\s+cached project version scan",
        "parent_versions_scanned": (
            r"cached project version scan\(s\);\s+scanning\s+(\d+)"
        ),
        "api_cache_entries_loaded": (
            r"Loaded API cache .*? with\s+(\d+)\s+entr"
        ),
        "rolled_up_vulnerabilities": (
            r"Found\s+(\d+)\s+rolled-up vulnerabilities"
        ),
    }

    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            metrics[name] = int(matches[-1])

    return {
        "stage_seconds": stage_seconds,
        "metrics": metrics,
    }


def read_pipeline_summary(output_root: Path) -> dict[str, Any]:
    path = output_root / "jira" / "pipeline-run-summary.json"

    if not path.is_file():
        return {}

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    stages: dict[str, Any] = {}

    for stage in payload.get("stages", []):
        if not isinstance(stage, dict):
            continue

        name = str(stage.get("name") or "")
        if name:
            stages[name] = {
                "status": stage.get("status"),
                "exit_code": stage.get("exit_code"),
                "elapsed_seconds": stage.get("elapsed_seconds"),
            }

    return {
        "run_id": payload.get("run_id"),
        "status": payload.get("status"),
        "exit_code": payload.get("exit_code"),
        "elapsed_seconds": payload.get("elapsed_seconds"),
        "source_counts": payload.get("source_counts", {}),
        "failure_counts": payload.get("failure_counts", {}),
        "hierarchy_counts": payload.get("hierarchy_counts", {}),
        "stages": stages,
    }


def normalized_pipeline_args(
    base_arguments: list[str],
    workers: int,
    config_path: str,
) -> list[str]:
    value_options = {
        "--workers",
        "--parent-workers",
        "--config",
    }
    removed_options = value_options | {
        "--apply",
        "--dry-run",
    }
    normalized: list[str] = []
    skip_next = False

    for argument in base_arguments:
        if skip_next:
            skip_next = False
            continue

        option = argument.split("=", 1)[0]

        if option in removed_options:
            if option in value_options and "=" not in argument:
                skip_next = True
            continue

        normalized.append(argument)

    return [
        "--dry-run",
        *normalized,
        "--workers",
        str(workers),
        "--parent-workers",
        str(workers),
        "--config",
        config_path,
    ]


def build_docker_command(
    docker_config: dict[str, Any],
    *,
    project_root: Path,
    output_root: Path,
    host_config_path: Path,
    pipeline_arguments: list[str],
    environment_names: list[str],
    container_name: str,
) -> list[str]:
    command = [
        str(docker_config.get("command") or "docker"),
        "run",
        "--rm",
        "--name",
        container_name,
    ]

    if docker_config.get("read_only", True):
        command.append("--read-only")

    cpus = docker_config.get("cpus")
    if cpus not in (None, ""):
        command.extend(["--cpus", str(cpus)])

    memory = docker_config.get("memory")
    if memory:
        command.extend(["--memory", str(memory)])

    command.extend(
        [
            "--tmpfs",
            str(docker_config.get("tmpfs") or "/tmp:rw,size=1g"),
            "--env",
            "HARNESS_OUTPUT_DIR=/benchmark-output",
            "--env",
            "TMPDIR=/tmp",
            "--volume",
            f"{output_root}:/benchmark-output",
            "--volume",
            (
                f"{host_config_path}:"
                "/etc/blackduck-harness/benchmark-config.json:ro"
            ),
        ]
    )

    for environment_name in environment_names:
        command.extend(["--env", environment_name])

    for argument in docker_config.get("extra_run_args", []):
        command.append(str(argument))

    image = str(docker_config.get("image") or "").strip()
    if not image:
        raise RuntimeError("docker.image must be configured")

    command.append(image)
    command.extend(pipeline_arguments)
    return command


def safe_kubernetes_name(value: str) -> str:
    value = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    value = re.sub(r"-+", "-", value)
    return (value or "benchmark")[:63].rstrip("-")


def build_job_manifest(
    cronjob: dict[str, Any],
    *,
    namespace: str,
    job_name: str,
    container_name: str,
    data_volume_name: str,
    storage_mode: str,
    pvc_claim_name: str,
    pipeline_arguments: list[str],
    active_deadline_seconds: int,
    resource_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    job_spec = copy.deepcopy(cronjob["spec"]["jobTemplate"]["spec"])
    job_spec["backoffLimit"] = 0
    job_spec["activeDeadlineSeconds"] = active_deadline_seconds
    job_spec.pop("selector", None)
    job_spec.pop("manualSelector", None)

    template = job_spec["template"]
    template.pop("status", None)
    template.setdefault("metadata", {}).setdefault("labels", {})
    template["metadata"]["labels"]["app.kubernetes.io/component"] = (
        "scaling-benchmark"
    )
    pod_spec = template["spec"]

    selected_container: dict[str, Any] | None = None
    for container in pod_spec.get("containers", []):
        if container.get("name") == container_name:
            selected_container = container
            break

    if selected_container is None:
        raise RuntimeError(
            f"Container {container_name!r} was not found in CronJob"
        )

    selected_container["args"] = list(pipeline_arguments)

    if resource_override:
        selected_container["resources"] = copy.deepcopy(resource_override)

    volumes = pod_spec.setdefault("volumes", [])
    selected_volume: dict[str, Any] | None = None

    for volume in volumes:
        if volume.get("name") == data_volume_name:
            selected_volume = volume
            break

    if selected_volume is None:
        raise RuntimeError(
            f"Volume {data_volume_name!r} was not found in CronJob"
        )

    selected_volume.clear()
    selected_volume["name"] = data_volume_name

    if storage_mode == "emptydir":
        selected_volume["emptyDir"] = {"sizeLimit": "5Gi"}
    elif storage_mode == "pvc":
        if not pvc_claim_name:
            raise RuntimeError("A benchmark PVC claim name is required")
        selected_volume["persistentVolumeClaim"] = {
            "claimName": pvc_claim_name
        }
    else:
        raise RuntimeError(f"Unsupported storage mode: {storage_mode}")

    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "blackduck-harness",
                "app.kubernetes.io/component": "scaling-benchmark",
            },
        },
        "spec": job_spec,
    }


def load_cronjob(
    project_root: Path,
    namespace: str,
    cronjob_name: str,
    kubectl: str,
) -> tuple[dict[str, Any] | None, str]:
    return_code, output = run_capture(
        [
            kubectl,
            "get",
            "cronjob",
            cronjob_name,
            "--namespace",
            namespace,
            "--output",
            "json",
        ],
        cwd=project_root,
    )

    if return_code != 0:
        return None, output

    try:
        return json.loads(output), ""
    except json.JSONDecodeError as error:
        return None, str(error)


def ensure_benchmark_pvc(
    project_root: Path,
    kubernetes_config: dict[str, Any],
    claim_name: str,
) -> tuple[bool, str]:
    kubectl = str(kubernetes_config.get("kubectl") or "kubectl")
    namespace = str(kubernetes_config["namespace"])

    return_code, output = run_capture(
        [
            kubectl,
            "get",
            "pvc",
            claim_name,
            "--namespace",
            namespace,
            "--output",
            "json",
        ],
        cwd=project_root,
    )

    if return_code == 0:
        return False, ""

    if not kubernetes_config.get("create_pvc", True):
        return False, output

    pvc_spec: dict[str, Any] = {
        "accessModes": ["ReadWriteOnce"],
        "resources": {
            "requests": {
                "storage": str(
                    kubernetes_config.get("pvc_size") or "5Gi"
                )
            }
        },
    }

    storage_class = str(
        kubernetes_config.get("storage_class") or ""
    ).strip()
    if storage_class:
        pvc_spec["storageClassName"] = storage_class

    manifest = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": claim_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/component": "scaling-benchmark"
            },
        },
        "spec": pvc_spec,
    }

    return_code, output = run_capture(
        [kubectl, "apply", "--filename", "-"],
        cwd=project_root,
        input_text=json.dumps(manifest),
    )

    if return_code != 0:
        return False, output

    return True, ""


def delete_kubernetes_resource(
    project_root: Path,
    kubectl: str,
    namespace: str,
    kind: str,
    name: str,
) -> None:
    run_capture(
        [
            kubectl,
            "delete",
            kind,
            name,
            "--namespace",
            namespace,
            "--ignore-not-found=true",
            "--wait=false",
        ],
        cwd=project_root,
    )


def parse_kubernetes_pod_info(payload: dict[str, Any]) -> dict[str, Any]:
    exit_codes: list[int] = []
    restart_count = 0
    elapsed_values: list[float] = []

    for pod in payload.get("items", []):
        for status in pod.get("status", {}).get(
            "containerStatuses",
            [],
        ):
            restart_count += int(status.get("restartCount") or 0)
            terminated = status.get("state", {}).get("terminated")

            if not isinstance(terminated, dict):
                terminated = status.get("lastState", {}).get("terminated")

            if not isinstance(terminated, dict):
                continue

            if terminated.get("exitCode") is not None:
                exit_codes.append(int(terminated["exitCode"]))

            started_at = str(terminated.get("startedAt") or "")
            finished_at = str(terminated.get("finishedAt") or "")

            if started_at and finished_at:
                try:
                    started = datetime.fromisoformat(
                        started_at.replace("Z", "+00:00")
                    )
                    finished = datetime.fromisoformat(
                        finished_at.replace("Z", "+00:00")
                    )
                    elapsed_values.append(
                        max(0.0, (finished - started).total_seconds())
                    )
                except ValueError:
                    pass

    return {
        "pod_exit_code": max(exit_codes) if exit_codes else None,
        "pod_restart_count": restart_count,
        "pod_elapsed_seconds": (
            round(max(elapsed_values), 3) if elapsed_values else None
        ),
    }


def run_kubernetes_job(
    *,
    project_root: Path,
    cronjob: dict[str, Any],
    kubernetes_config: dict[str, Any],
    storage_mode: str,
    pvc_claim_name: str,
    pipeline_arguments: list[str],
    job_name: str,
    log_path: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    kubectl = str(kubernetes_config.get("kubectl") or "kubectl")
    namespace = str(kubernetes_config["namespace"])
    poll_seconds = float(kubernetes_config.get("poll_seconds") or 5)
    manifest = build_job_manifest(
        cronjob,
        namespace=namespace,
        job_name=job_name,
        container_name=str(
            kubernetes_config.get("container_name") or "jira-pipeline"
        ),
        data_volume_name=str(
            kubernetes_config.get("data_volume_name") or "harness-data"
        ),
        storage_mode=storage_mode,
        pvc_claim_name=pvc_claim_name,
        pipeline_arguments=pipeline_arguments,
        active_deadline_seconds=timeout_seconds,
        resource_override=kubernetes_config.get("resources"),
    )

    started_at = utc_now()
    started = time.monotonic()
    timed_out = False
    error = ""
    return_code, output = run_capture(
        [kubectl, "apply", "--filename", "-"],
        cwd=project_root,
        input_text=json.dumps(manifest),
    )
    append_log(log_path, output)

    if return_code == 0:
        deadline = time.monotonic() + timeout_seconds

        while time.monotonic() < deadline:
            status_code, status_output = run_capture(
                [
                    kubectl,
                    "get",
                    "job",
                    job_name,
                    "--namespace",
                    namespace,
                    "--output",
                    "json",
                ],
                cwd=project_root,
            )

            if status_code != 0:
                error = status_output
                return_code = status_code
                break

            try:
                status_payload = json.loads(status_output)
            except json.JSONDecodeError as caught:
                error = str(caught)
                return_code = 1
                break

            status = status_payload.get("status", {})

            if int(status.get("succeeded") or 0) >= 1:
                return_code = 0
                break

            failed_condition = any(
                condition.get("type") == "Failed"
                and condition.get("status") == "True"
                for condition in status.get("conditions", [])
            )

            if failed_condition:
                return_code = 1
                break

            time.sleep(poll_seconds)
        else:
            timed_out = True
            return_code = 124

    logs_code, logs_output = run_capture(
        [
            kubectl,
            "logs",
            "--namespace",
            namespace,
            f"job/{job_name}",
            "--all-containers=true",
        ],
        cwd=project_root,
        timeout=120,
    )
    append_log(log_path, logs_output)

    if logs_code != 0 and not error:
        error = logs_output

    pod_code, pod_output = run_capture(
        [
            kubectl,
            "get",
            "pods",
            "--namespace",
            namespace,
            "--selector",
            f"job-name={job_name}",
            "--output",
            "json",
        ],
        cwd=project_root,
    )

    pod_info: dict[str, Any] = {
        "pod_exit_code": None,
        "pod_restart_count": 0,
        "pod_elapsed_seconds": None,
    }

    if pod_code == 0:
        try:
            pod_info = parse_kubernetes_pod_info(
                json.loads(pod_output)
            )
        except json.JSONDecodeError:
            pass

    if pod_info.get("pod_exit_code") not in (None, 0):
        return_code = int(pod_info["pod_exit_code"])

    if kubernetes_config.get("cleanup_jobs", True):
        delete_kubernetes_resource(
            project_root,
            kubectl,
            namespace,
            "job",
            job_name,
        )

    return {
        "started_at": started_at,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "return_code": return_code,
        "timed_out": timed_out,
        "launcher_user_seconds": None,
        "launcher_system_seconds": None,
        "command": [
            kubectl,
            "apply",
            "--filename",
            "<generated-job-manifest>",
        ],
        "log_path": str(log_path),
        "error": error,
        **pod_info,
    }


def write_reports(
    run_directory: Path,
    records: list[dict[str, Any]],
) -> None:
    atomic_write_json(
        run_directory / "results.json",
        {
            "generated_at": utc_now(),
            "result_count": len(records),
            "results": records,
        },
    )

    csv_path = run_directory / "results.csv"
    temporary = csv_path.with_name(
        f"{csv_path.name}.{uuid.uuid4().hex}.tmp"
    )

    with temporary.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for record in records:
            row: dict[str, Any] = {}

            for field in CSV_FIELDS:
                value = record.get(field, "")
                if isinstance(value, (dict, list)):
                    value = json.dumps(
                        value,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                row[field] = value

            writer.writerow(row)

    os.replace(temporary, csv_path)


def resolve_path(project_root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else project_root / path


def load_configuration(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Benchmark configuration must be an object")
    return payload


def scenario_names(configuration: dict[str, Any]) -> list[str]:
    names: list[str] = []

    if configuration.get("local", {}).get("enabled"):
        names.append("local")

    if configuration.get("docker", {}).get("enabled"):
        names.append("docker")

    kubernetes = configuration.get("kubernetes", {})
    if kubernetes.get("enabled"):
        for storage_mode in kubernetes.get(
            "storage_modes",
            ["emptydir", "pvc"],
        ):
            names.append(f"k8s-{storage_mode}")

    return names


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run silent local, container and Kubernetes scaling benchmarks."
    )
    parser.add_argument(
        "--config",
        default="scripts/scaling_benchmark.json",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=["local", "docker", "k8s-emptydir", "k8s-pvc"],
    )
    parser.add_argument("--results-dir")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    config_path = resolve_path(project_root, args.config)
    configuration = load_configuration(config_path)
    results_root = resolve_path(
        project_root,
        args.results_dir
        or str(configuration.get("results_dir") or ".benchmark-results"),
    )
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    run_directory = results_root / run_id
    run_directory.mkdir(parents=True, exist_ok=False)

    selected_scenarios = args.scenario or scenario_names(configuration)
    workers_values = [
        int(value)
        for value in configuration.get("workers", [1, 2, 4])
    ]
    repetitions = int(configuration.get("repetitions") or 2)
    timeout_seconds = int(
        configuration.get("timeout_seconds") or 21600
    )
    base_arguments = [
        str(value)
        for value in configuration.get(
            "pipeline_args",
            ["--dry-run", "--strict"],
        )
    ]
    jira_config = resolve_path(
        project_root,
        str(configuration["jira_config"]),
    )
    environment_names = [
        str(value)
        for value in configuration.get(
            "environment_names",
            [
                "BLACKDUCK_URL",
                "BLACKDUCK_API_TOKEN",
                "JIRA_URL",
                "JIRA_USER",
                "JIRA_API_TOKEN",
                "JIRA_PAT",
                "SSL_CERT_FILE",
            ],
        )
    ]

    records: list[dict[str, Any]] = []
    kubernetes_config = configuration.get("kubernetes", {})
    cronjob: dict[str, Any] | None = None
    cronjob_error = ""
    created_claims: list[str] = []

    if any(name.startswith("k8s-") for name in selected_scenarios):
        cronjob, cronjob_error = load_cronjob(
            project_root,
            str(kubernetes_config["namespace"]),
            str(kubernetes_config["cronjob"]),
            str(kubernetes_config.get("kubectl") or "kubectl"),
        )

    try:
        for scenario in selected_scenarios:
            for workers in workers_values:
                output_root = (
                    run_directory
                    / "runtime"
                    / scenario
                    / f"workers-{workers}"
                )
                output_root.mkdir(parents=True, exist_ok=True)

                claim_name = ""
                claim_error = ""

                if scenario == "k8s-pvc":
                    explicit_claim = str(
                        kubernetes_config.get("pvc_claim_name") or ""
                    ).strip()
                    claim_name = explicit_claim or safe_kubernetes_name(
                        f"bd-bench-{run_id[-8:]}-w{workers}"
                    )
                    created, claim_error = ensure_benchmark_pvc(
                        project_root,
                        kubernetes_config,
                        claim_name,
                    )
                    if created:
                        created_claims.append(claim_name)

                for iteration in range(1, repetitions + 1):
                    cache_state = (
                        "warm"
                        if iteration > 1
                        and scenario in {"local", "docker", "k8s-pvc"}
                        else "cold"
                    )
                    log_path = (
                        run_directory
                        / "logs"
                        / scenario
                        / f"workers-{workers}"
                        / f"iteration-{iteration}.log"
                    )
                    record: dict[str, Any] = {
                        "scenario": scenario,
                        "workers": workers,
                        "iteration": iteration,
                        "cache_state": cache_state,
                        "pod_elapsed_seconds": None,
                        "pod_exit_code": None,
                        "pod_restart_count": None,
                        "stage_seconds": {},
                        "metrics": {},
                        "pipeline_summary": {},
                        "error": "",
                    }

                    try:
                        if scenario == "local":
                            local_config = configuration.get("local", {})
                            pipeline_arguments = normalized_pipeline_args(
                                base_arguments,
                                workers,
                                str(jira_config),
                            )
                            command = [
                                str(value)
                                for value in local_config.get(
                                    "command",
                                    [
                                        ".venv/bin/python",
                                        "-m",
                                        "harness.jira.pipeline",
                                    ],
                                )
                            ]
                            command.extend(pipeline_arguments)
                            environment = dict(os.environ)
                            environment["HARNESS_OUTPUT_DIR"] = str(
                                output_root
                            )
                            temporary_dir = output_root / "tmp"
                            temporary_dir.mkdir(
                                parents=True,
                                exist_ok=True,
                            )
                            environment["TMPDIR"] = str(temporary_dir)
                            execution = run_process(
                                command,
                                cwd=project_root,
                                environment=environment,
                                log_path=log_path,
                                timeout_seconds=timeout_seconds,
                            )
                            record.update(execution)
                            record["pipeline_summary"] = (
                                read_pipeline_summary(output_root)
                            )

                        elif scenario == "docker":
                            docker_config = configuration.get(
                                "docker",
                                {},
                            )
                            container_config_path = (
                                "/etc/blackduck-harness/"
                                "benchmark-config.json"
                            )
                            pipeline_arguments = normalized_pipeline_args(
                                base_arguments,
                                workers,
                                container_config_path,
                            )
                            container_name = safe_kubernetes_name(
                                f"bd-benchmark-{run_id[-8:]}-"
                                f"w{workers}-i{iteration}"
                            )
                            command = build_docker_command(
                                docker_config,
                                project_root=project_root,
                                output_root=output_root,
                                host_config_path=jira_config,
                                pipeline_arguments=pipeline_arguments,
                                environment_names=environment_names,
                                container_name=container_name,
                            )
                            execution = run_process(
                                command,
                                cwd=project_root,
                                environment=dict(os.environ),
                                log_path=log_path,
                                timeout_seconds=timeout_seconds,
                            )
                            record.update(execution)
                            record["pipeline_summary"] = (
                                read_pipeline_summary(output_root)
                            )

                        elif scenario.startswith("k8s-"):
                            if cronjob is None:
                                raise RuntimeError(
                                    cronjob_error
                                    or "Could not load Kubernetes CronJob"
                                )

                            if claim_error:
                                raise RuntimeError(claim_error)

                            storage_mode = scenario.removeprefix("k8s-")
                            kubernetes_config_path = str(
                                kubernetes_config.get("config_path")
                                or (
                                    "/etc/blackduck-harness/"
                                    "jira-rollup-config.json"
                                )
                            )
                            pipeline_arguments = normalized_pipeline_args(
                                base_arguments,
                                workers,
                                kubernetes_config_path,
                            )
                            job_name = safe_kubernetes_name(
                                f"bd-bench-{run_id[-8:]}-"
                                f"{storage_mode}-w{workers}-i{iteration}"
                            )
                            execution = run_kubernetes_job(
                                project_root=project_root,
                                cronjob=cronjob,
                                kubernetes_config=kubernetes_config,
                                storage_mode=storage_mode,
                                pvc_claim_name=claim_name,
                                pipeline_arguments=pipeline_arguments,
                                job_name=job_name,
                                log_path=log_path,
                                timeout_seconds=timeout_seconds,
                            )
                            record.update(execution)

                        else:
                            raise RuntimeError(
                                f"Unsupported scenario: {scenario}"
                            )

                    except Exception as caught:
                        record.update(
                            {
                                "started_at": utc_now(),
                                "elapsed_seconds": 0,
                                "return_code": 70,
                                "timed_out": False,
                                "launcher_user_seconds": None,
                                "launcher_system_seconds": None,
                                "command": [],
                                "log_path": str(log_path),
                                "error": str(caught),
                            }
                        )
                        append_log(log_path, str(caught))

                    parsed_log = parse_pipeline_log(log_path)
                    record["stage_seconds"] = parsed_log[
                        "stage_seconds"
                    ]
                    record["metrics"] = parsed_log["metrics"]
                    records.append(record)
                    write_reports(run_directory, records)

    finally:
        if kubernetes_config.get("cleanup_pvc", True):
            kubectl = str(
                kubernetes_config.get("kubectl") or "kubectl"
            )
            namespace = str(
                kubernetes_config.get("namespace") or ""
            )

            for claim_name in created_claims:
                delete_kubernetes_resource(
                    project_root,
                    kubectl,
                    namespace,
                    "pvc",
                    claim_name,
                )

    failed_count = sum(
        1
        for record in records
        if int(record.get("return_code") or 0) != 0
    )
    atomic_write_json(
        results_root / "latest-run.json",
        {
            "run_id": run_id,
            "run_directory": str(run_directory),
            "result_count": len(records),
            "failed_count": failed_count,
        },
    )
    return 1 if failed_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
