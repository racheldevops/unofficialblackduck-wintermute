from __future__ import annotations

import importlib.util
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "scripts" / "scaling_benchmark.py"
SPEC = importlib.util.spec_from_file_location(
    "scaling_benchmark",
    MODULE_PATH,
)
assert SPEC is not None
assert SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def test_normalized_pipeline_args_force_dry_run_and_workers() -> None:
    arguments = benchmark.normalized_pipeline_args(
        [
            "--apply",
            "--strict",
            "--workers",
            "99",
            "--parent-workers=88",
            "--config",
            "old.json",
        ],
        workers=4,
        config_path="new.json",
    )

    assert "--apply" not in arguments
    assert arguments.count("--dry-run") == 1
    assert arguments[arguments.index("--workers") + 1] == "4"
    assert arguments[arguments.index("--parent-workers") + 1] == "4"
    assert arguments[arguments.index("--config") + 1] == "new.json"
    assert "99" not in arguments
    assert "old.json" not in arguments


def test_redact_command_hides_inline_and_positional_secrets() -> None:
    command = benchmark.redact_command(
        [
            "program",
            "--api-token",
            "secret-one",
            "PASSWORD=secret-two",
            "--safe",
            "value",
        ]
    )

    rendered = " ".join(command)
    assert "secret-one" not in rendered
    assert "secret-two" not in rendered
    assert "--safe value" in rendered


def test_parse_pipeline_log_extracts_stages_and_metrics(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "pipeline.log"
    log_path.write_text(
        "\n".join(
            [
                "Indexed 120 project versions.",
                (
                    "Reusing 100 cached project version scan(s); "
                    "scanning 20 project version(s)."
                ),
                (
                    "Loaded API cache from cache.json with "
                    "45 entrie(s)."
                ),
                "Reusing API cache: https://example.invalid/a",
                "Retrying request after HTTP 429",
                (
                    "Pipeline stage completed: find-parent-projects "
                    "in 12.5s"
                ),
                (
                    "Pipeline stage completed: "
                    "collect-vulnerability-rollup in 31.25s"
                ),
                (
                    "Found 73 rolled-up vulnerabilities with "
                    "overallScore >= 7.0"
                ),
            ]
        ),
        encoding="utf-8",
    )

    parsed = benchmark.parse_pipeline_log(log_path)

    assert parsed["stage_seconds"] == {
        "find-parent-projects": 12.5,
        "collect-vulnerability-rollup": 31.25,
    }
    assert parsed["metrics"]["indexed_project_versions"] == 120
    assert parsed["metrics"]["parent_cache_reused"] == 100
    assert parsed["metrics"]["parent_versions_scanned"] == 20
    assert parsed["metrics"]["api_cache_entries_loaded"] == 45
    assert parsed["metrics"]["api_cache_hit_lines"] == 1
    assert parsed["metrics"]["retry_lines"] == 1
    assert parsed["metrics"]["http_429_lines"] == 1
    assert parsed["metrics"]["rolled_up_vulnerabilities"] == 73


def sample_cronjob() -> dict:
    return {
        "spec": {
            "jobTemplate": {
                "spec": {
                    "backoffLimit": 1,
                    "template": {
                        "metadata": {
                            "labels": {
                                "existing": "label"
                            }
                        },
                        "spec": {
                            "restartPolicy": "Never",
                            "containers": [
                                {
                                    "name": "jira-pipeline",
                                    "image": "example.invalid/image:test",
                                    "args": ["--apply"],
                                    "volumeMounts": [
                                        {
                                            "name": "wintermute-data",
                                            "mountPath": "/data",
                                        }
                                    ],
                                }
                            ],
                            "volumes": [
                                {
                                    "name": "wintermute-data",
                                    "persistentVolumeClaim": {
                                        "claimName": "production-data"
                                    },
                                }
                            ],
                        },
                    },
                }
            }
        }
    }


def test_build_job_manifest_replaces_production_pvc_with_emptydir() -> None:
    original = sample_cronjob()

    manifest = benchmark.build_job_manifest(
        original,
        namespace="benchmark",
        job_name="benchmark-job",
        container_name="jira-pipeline",
        data_volume_name="wintermute-data",
        storage_mode="emptydir",
        pvc_claim_name="",
        pipeline_arguments=["--dry-run", "--workers", "4"],
        active_deadline_seconds=600,
    )

    job_spec = manifest["spec"]
    pod_spec = job_spec["template"]["spec"]
    container = pod_spec["containers"][0]
    volume = pod_spec["volumes"][0]

    assert manifest["kind"] == "Job"
    assert manifest["metadata"]["namespace"] == "benchmark"
    assert job_spec["backoffLimit"] == 0
    assert job_spec["activeDeadlineSeconds"] == 600
    assert container["args"] == ["--dry-run", "--workers", "4"]
    assert volume["name"] == "wintermute-data"
    assert "emptyDir" in volume
    assert "persistentVolumeClaim" not in volume
    assert (
        original["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        ["volumes"][0]["persistentVolumeClaim"]["claimName"]
        == "production-data"
    )


def test_build_job_manifest_uses_isolated_benchmark_pvc() -> None:
    manifest = benchmark.build_job_manifest(
        sample_cronjob(),
        namespace="benchmark",
        job_name="benchmark-job",
        container_name="jira-pipeline",
        data_volume_name="wintermute-data",
        storage_mode="pvc",
        pvc_claim_name="benchmark-data",
        pipeline_arguments=["--dry-run"],
        active_deadline_seconds=600,
    )

    volume = manifest["spec"]["template"]["spec"]["volumes"][0]

    assert volume == {
        "name": "wintermute-data",
        "persistentVolumeClaim": {
            "claimName": "benchmark-data"
        },
    }


def test_docker_command_passes_secret_names_not_values(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "never-render-this")

    output_root = tmp_path / "output"
    output_root.mkdir()
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")

    command = benchmark.build_docker_command(
        {
            "command": "docker",
            "image": "example.invalid/image:test",
            "read_only": True,
            "cpus": 2,
            "memory": "2g",
        },
        project_root=PROJECT_ROOT,
        output_root=output_root,
        host_config_path=config_path,
        pipeline_arguments=["--dry-run"],
        environment_names=["BLACKDUCK_API_TOKEN"],
        container_name="benchmark",
    )

    rendered = " ".join(command)

    assert "--env BLACKDUCK_API_TOKEN" in rendered
    assert "never-render-this" not in rendered
    assert "--read-only" in command
    assert "example.invalid/image:test" in command


def test_read_pipeline_summary_excludes_stage_arguments(
    tmp_path: Path,
) -> None:
    summary_path = tmp_path / "jira" / "pipeline-run-summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "status": "succeeded",
                "exit_code": 0,
                "elapsed_seconds": 10,
                "source_counts": {"findings": 2},
                "failure_counts": {},
                "hierarchy_counts": {},
                "stages": [
                    {
                        "name": "stage-one",
                        "status": "succeeded",
                        "exit_code": 0,
                        "elapsed_seconds": 4,
                        "arguments": [
                            "--api-token",
                            "must-not-be-copied",
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    summary = benchmark.read_pipeline_summary(tmp_path)
    rendered = json.dumps(summary)

    assert summary["run_id"] == "run-1"
    assert summary["stages"]["stage-one"]["elapsed_seconds"] == 4
    assert "arguments" not in rendered
    assert "must-not-be-copied" not in rendered


def test_normalized_pipeline_args_sets_rollup_workers() -> None:
    arguments = benchmark.normalized_pipeline_args(
        [
            "--dry-run",
            "--rollup-workers",
            "99",
            "--config",
            "old.json",
        ],
        workers=4,
        config_path="new.json",
    )

    assert arguments.count("--rollup-workers") == 1
    assert arguments[
        arguments.index("--rollup-workers") + 1
    ] == "4"
    assert "99" not in arguments
