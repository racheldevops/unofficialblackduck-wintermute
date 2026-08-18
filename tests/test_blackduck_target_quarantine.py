from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from wintermute.blackduck import collector
from wintermute.blackduck.criteria import (
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.models import (
    CollectionTarget,
    LineageContext,
    ProjectVersionRef,
)
from wintermute.blackduck.request_control import (
    BlackDuckCircuitOpenError,
    BlackDuckRequestController,
    current_request_context,
)


def target() -> CollectionTarget:
    child = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Example-Child",
        version="1.0.0",
        version_href=(
            "https://bd.example/api/projects/child/"
            "versions/version"
        ),
    )
    parent = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Example-Parent",
        version="2.0.0",
        version_href=(
            "https://bd.example/api/projects/parent/"
            "versions/version"
        ),
    )

    return CollectionTarget(
        project_version=child,
        lineage_contexts=(
            LineageContext(
                parent=parent,
                child=child,
            ),
        ),
    )


def test_collector_attaches_target_context() -> None:
    shared = BlackDuckRequestController(
        request_interval_seconds=0,
        circuit_breaker_threshold=1,
        circuit_breaker_window_seconds=60,
    )
    seen: dict[str, str] = {}

    class Client:
        request_control = shared

        def paged_get(
            self,
            url: str,
        ) -> list[dict[str, Any]]:
            del url
            seen.update(current_request_context())
            shared.record_server_failure(
                502,
                "https://bd.example/api/failure",
                context=current_request_context(),
            )
            raise shared.circuit_error()

    with pytest.raises(
        BlackDuckCircuitOpenError,
    ):
        collector.collect_target(
            Client(),
            target(),
            jira_parent_rollup_criteria(),
        )

    assert seen["child_project"] == "Example-Child"
    assert seen["child_version"] == "1.0.0"
    assert seen["parent_projects"] == "Example-Parent"


def test_active_quarantine_skips_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "WINTERMUTE_OUTPUT_DIR",
        str(tmp_path),
    )
    path = (
        tmp_path
        / "jira"
        / "state"
        / "blackduck-circuit-quarantine.json"
    )
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "status": "active",
                "target": {
                    "child_project": "Example-Child",
                    "child_version": "1.0.0",
                    "child_version_href": (
                        "https://bd.example/api/projects/child/"
                        "versions/version"
                    ),
                    "parent_projects": [
                        "Example-Parent"
                    ],
                    "retry_after_epoch": (
                        time.time() + 600
                    ),
                    "retry_after": "later",
                    "failure_count": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    class Client:
        def paged_get(
            self,
            url: str,
        ) -> list[dict[str, Any]]:
            raise AssertionError(
                f"Quarantined target made a request: {url}"
            )

    result = collector.collect_targets(
        Client(),
        [target()],
        jira_parent_rollup_criteria(),
        workers=1,
    )

    assert len(result.target_results) == 1
    assert (
        result.target_results[0]
        .failures[0]
        .stage
        == "temporary-quarantine"
    )


def test_pipeline_stage_uses_circuit_recovery() -> None:
    from wintermute.jira import pipeline

    assert (
        "run_with_circuit_recovery"
        in pipeline.run_stage.__code__.co_names
    )
