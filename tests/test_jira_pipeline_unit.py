from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from wintermute.jira import pipeline


def valid_pipeline_args(**overrides: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "max_create": None,
        "timeout": 60,
        "retries": 2,
        "retry_delay": 2.0,
        "page_limit": 500,
        "workers": 2,
        "parent_workers": None,
        "retain_runs": 3,
        "lock_stale_seconds": 3600,
        "apply": False,
        "dry_run": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_stale_pipeline_lock_is_archived(tmp_path: Path) -> None:
    lock_path = tmp_path / "pipeline.lock"
    lock_path.write_text(
        json.dumps({"run_id": "old"}),
        encoding="utf-8",
    )
    stale_time = time.time() - 7200
    os.utime(lock_path, (stale_time, stale_time))

    with pipeline.PipelineLock(
        lock_path,
        "new-run",
        stale_seconds=60,
    ):
        assert lock_path.exists()
        active = json.loads(lock_path.read_text(encoding="utf-8"))
        assert active["run_id"] == "new-run"

    assert not lock_path.exists()
    assert (tmp_path / "pipeline.lock.stale-new-run").exists()


def test_pipeline_lock_only_removes_its_own_token(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "pipeline.lock"

    with pipeline.PipelineLock(lock_path, "run", 3600):
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
        payload["token"] = "replacement"
        lock_path.write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

    assert lock_path.exists()


def test_invoke_module_main_restores_sys_argv() -> None:
    original = list(sys.argv)
    captured: list[str] = []

    def main() -> int:
        captured.extend(sys.argv)
        return 7

    module = SimpleNamespace(
        __name__="fake.module",
        main=main,
    )

    assert pipeline.invoke_module_main(module, ["one", "two"]) == 7
    assert captured == ["fake.module", "one", "two"]
    assert sys.argv == original


def test_invoke_module_main_handles_system_exit() -> None:
    def main() -> None:
        raise SystemExit(9)

    module = SimpleNamespace(
        __name__="fake.exit",
        main=main,
    )

    assert pipeline.invoke_module_main(module, []) == 9


def test_run_stage_records_success_and_checks_outputs(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output.json"
    summary: dict[str, Any] = {}

    def main() -> int:
        output.write_text("{}", encoding="utf-8")
        return 0

    module = SimpleNamespace(
        __name__="fake.success",
        main=main,
    )

    pipeline.run_stage(
        summary,
        "stage",
        module,
        ["--example"],
        [output],
    )

    assert summary["stages"][0]["status"] == "succeeded"
    assert summary["stages"][0]["exit_code"] == 0
    assert summary["stages"][0]["arguments"] == ["--example"]


def test_run_stage_rejects_missing_output(tmp_path: Path) -> None:
    output = tmp_path / "missing.json"
    summary: dict[str, Any] = {}
    module = SimpleNamespace(
        __name__="fake.missing",
        main=lambda: 0,
    )

    with pytest.raises(pipeline.PipelineFailure) as captured:
        pipeline.run_stage(
            summary,
            "stage",
            module,
            [],
            [output],
        )

    assert (
        captured.value.exit_code
        == pipeline.EXIT_REQUIRED_OUTPUT_MISSING
    )
    assert summary["stages"][0]["status"] == "failed"
    assert str(output) in summary["stages"][0]["missing_outputs"]


def test_run_stage_propagates_nonzero_exit_code() -> None:
    summary: dict[str, Any] = {}
    module = SimpleNamespace(
        __name__="fake.failure",
        main=lambda: 7,
    )

    with pytest.raises(pipeline.PipelineFailure) as captured:
        pipeline.run_stage(
            summary,
            "stage",
            module,
            [],
            [],
        )

    assert captured.value.exit_code == 7
    assert summary["stages"][0]["status"] == "failed"


def test_validate_environment_accepts_dry_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BLACKDUCK_URL", "https://bd.example")
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "token")
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "jira": {
                    "project_key": "SEC",
                    "auth_mode": "basic",
                }
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace(
        config=str(config_path),
        ca_bundle=None,
        insecure=True,
        apply=False,
    )

    result = pipeline.validate_environment(
        args,
        tmp_path / "output",
    )

    assert result["jira_project_key"] == "SEC"
    assert result["tls_mode"] == "insecure"


def test_validate_environment_requires_blackduck_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BLACKDUCK_URL", raising=False)
    monkeypatch.delenv("BLACKDUCK_API_TOKEN", raising=False)
    args = argparse.Namespace(
        config=str(tmp_path / "unused.json"),
        ca_bundle=None,
        insecure=False,
        apply=False,
    )

    with pytest.raises(pipeline.PipelineFailure) as captured:
        pipeline.validate_environment(args, tmp_path / "output")

    assert captured.value.exit_code == pipeline.EXIT_ARGUMENT_ERROR
    assert "BLACKDUCK_URL" in str(captured.value)


def test_validate_environment_requires_apply_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BLACKDUCK_URL", "https://bd.example")
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "token")
    monkeypatch.delenv("JIRA_USER", raising=False)
    monkeypatch.delenv("JIRA_API_TOKEN", raising=False)
    monkeypatch.delenv("JIRA_PAT", raising=False)
    monkeypatch.delenv("JIRA_URL", raising=False)

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "jira": {
                    "url": "https://jira.example",
                    "project_key": "SEC",
                    "auth_mode": "basic",
                }
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace(
        config=str(config_path),
        ca_bundle=None,
        insecure=False,
        apply=True,
    )

    with pytest.raises(pipeline.PipelineFailure) as captured:
        pipeline.validate_environment(args, tmp_path / "output")

    assert captured.value.exit_code == pipeline.EXIT_ARGUMENT_ERROR
    assert "JIRA_USER" in str(captured.value)


def test_validate_environment_sets_custom_ca(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BLACKDUCK_URL", "https://bd.example")
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "token")
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"jira": {"project_key": "SEC"}}),
        encoding="utf-8",
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_text("test-ca", encoding="utf-8")
    args = argparse.Namespace(
        config=str(config_path),
        ca_bundle=str(ca_path),
        insecure=False,
        apply=False,
    )

    result = pipeline.validate_environment(
        args,
        tmp_path / "output",
    )

    assert result["tls_mode"] == f"custom-ca:{ca_path}"
    assert os.environ["SSL_CERT_FILE"] == str(ca_path)


def test_count_parent_cache_failures(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    cache_path.write_text(
        json.dumps(
            {
                "entries": {
                    "ok": {"status": "ok"},
                    "failed-one": {"status": "failed"},
                    "failed-two": {"status": "failed"},
                    "invalid": "not-an-object",
                }
            }
        ),
        encoding="utf-8",
    )

    assert pipeline.count_parent_cache_failures(cache_path) == 2


def test_invalid_parent_cache_counts_as_failure(
    tmp_path: Path,
) -> None:
    cache_path = tmp_path / "cache.json"
    cache_path.write_text("{invalid", encoding="utf-8")

    assert pipeline.count_parent_cache_failures(cache_path) == 1


def test_ensure_empty_failure_report_writes_header(
    tmp_path: Path,
) -> None:
    path = tmp_path / "failures.csv"

    pipeline.ensure_empty_rollup_failure_report(path)

    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        assert reader.fieldnames is not None
        assert "child_version_href" in reader.fieldnames
        assert "error" in reader.fieldnames
        assert list(reader) == []


def test_promote_outputs_copies_only_known_files(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    active_dir = tmp_path / "active"
    run_dir.mkdir()
    (run_dir / "findings.csv").write_text(
        "header\n",
        encoding="utf-8",
    )
    (run_dir / "unknown.txt").write_text(
        "ignored",
        encoding="utf-8",
    )

    promoted = pipeline.promote_outputs(run_dir, active_dir)

    assert promoted == [str(active_dir / "findings.csv")]
    assert (active_dir / "findings.csv").read_text(
        encoding="utf-8"
    ) == "header\n"
    assert not (active_dir / "unknown.txt").exists()


def test_prune_run_directories_retains_current_and_newest_old(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()

    for name in ("20260101", "20260102", "current"):
        (runs / name).mkdir()

    pipeline.prune_run_directories(
        runs,
        current_run_id="current",
        retain_count=2,
    )

    assert (runs / "current").exists()
    assert (runs / "20260102").exists()
    assert not (runs / "20260101").exists()


def test_validate_args_populates_worker_defaults() -> None:
    args = valid_pipeline_args(workers=3)

    pipeline.validate_args(args)

    assert args.parent_workers == 3
    assert args.dry_run is True
    assert args.resolve_bom_names is False
    assert args.allow_empty is False


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"workers": 0}, "workers"),
        ({"page_limit": 0}, "page-limit"),
        ({"retain_runs": 0}, "retain-runs"),
        ({"lock_stale_seconds": 59}, "lock-stale-seconds"),
        ({"max_create": 0}, "max-create"),
    ],
)
def test_validate_args_rejects_invalid_values(
    override: dict[str, Any],
    message: str,
) -> None:
    args = valid_pipeline_args(**override)

    with pytest.raises(pipeline.PipelineFailure) as captured:
        pipeline.validate_args(args)

    assert captured.value.exit_code == pipeline.EXIT_ARGUMENT_ERROR
    assert message in str(captured.value)


def test_load_config_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(pipeline.PipelineFailure) as captured:
        pipeline.load_config(path)

    assert captured.value.exit_code == pipeline.EXIT_ARGUMENT_ERROR
