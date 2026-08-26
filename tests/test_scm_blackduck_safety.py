from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from wintermute.blackduck.request_control import (
    DEFAULT_REQUEST_INTERVAL_SECONDS,
    BlackDuckCircuitOpenError,
    BlackDuckRequestController,
    current_request_context,
)
from wintermute.scm.coverage import blackduck_scan
from wintermute.scm.coverage import cli as coverage_cli
from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckProjectObservation,
    BlackDuckVersionObservation,
)


VERSION_HREF = (
    "https://bd.example/api/projects/project-id/"
    "versions/version-id"
)
BOM_STATUS_HREF = (
    f"{VERSION_HREF}/bom-status"
)
CODE_LOCATIONS_HREF = (
    f"{VERSION_HREF}/codelocations"
)
SCAN_SUMMARIES_HREF = (
    f"{CODE_LOCATIONS_HREF}/scan-summaries"
)


def project_and_version() -> tuple[
    BlackDuckProjectObservation,
    BlackDuckVersionObservation,
]:
    version = BlackDuckVersionObservation(
        project_id="project-id",
        version_id="version-id",
        name="1.0.0",
        href=VERSION_HREF,
    )
    project = BlackDuckProjectObservation(
        instance_url="https://bd.example",
        project_id="project-id",
        name="Example Project",
        href="https://bd.example/api/projects/project-id",
        versions=(version,),
    )

    return project, version


def open_circuit_error() -> BlackDuckCircuitOpenError:
    controller = BlackDuckRequestController(
        request_interval_seconds=0,
        circuit_breaker_threshold=1,
        circuit_breaker_window_seconds=60,
    )
    controller.record_server_failure(
        502,
        VERSION_HREF,
        context={
            "project": "Example Project",
            "project_version": "1.0.0",
            "project_version_href": VERSION_HREF,
            "stage": "scm-direct-scan-evidence",
        },
    )

    return controller.circuit_error()


def version_resource(
    *,
    bom_status: bool = False,
    code_locations: bool = False,
) -> dict[str, Any]:
    links: list[dict[str, str]] = []

    if bom_status:
        links.append(
            {
                "rel": "bom-status",
                "href": BOM_STATUS_HREF,
            }
        )

    if code_locations:
        links.append(
            {
                "rel": "code-locations",
                "href": CODE_LOCATIONS_HREF,
            }
        )

    return {
        "_meta": {
            "href": VERSION_HREF,
            "links": links,
        }
    }


def test_shared_blackduck_default_is_half_second() -> None:
    assert DEFAULT_REQUEST_INTERVAL_SECONDS == 0.5


def test_version_lookup_propagates_open_circuit() -> None:
    project, version = project_and_version()
    error = open_circuit_error()

    class Client:
        def get(
            self,
            url: str,
        ) -> dict[str, Any]:
            del url
            raise error

    with pytest.raises(
        BlackDuckCircuitOpenError,
    ):
        blackduck_scan.collect_version_evidence(
            Client(),
            project,
            version,
        )


def test_bom_status_lookup_propagates_open_circuit() -> None:
    project, version = project_and_version()
    error = open_circuit_error()

    class Client:
        def get(
            self,
            url: str,
        ) -> dict[str, Any]:
            if url == VERSION_HREF:
                return version_resource(
                    bom_status=True
                )

            assert url == BOM_STATUS_HREF
            raise error

    with pytest.raises(
        BlackDuckCircuitOpenError,
    ):
        blackduck_scan.collect_version_evidence(
            Client(),
            project,
            version,
        )


def test_code_location_lookup_propagates_open_circuit() -> None:
    project, version = project_and_version()
    error = open_circuit_error()

    class Client:
        def get(
            self,
            url: str,
        ) -> dict[str, Any]:
            assert url == VERSION_HREF
            return version_resource(
                code_locations=True
            )

        def paged_get(
            self,
            url: str,
        ) -> list[dict[str, Any]]:
            assert url == CODE_LOCATIONS_HREF
            raise error

    with pytest.raises(
        BlackDuckCircuitOpenError,
    ):
        blackduck_scan.collect_version_evidence(
            Client(),
            project,
            version,
        )


def test_scan_summary_lookup_propagates_open_circuit() -> None:
    project, version = project_and_version()
    error = open_circuit_error()

    class Client:
        def get(
            self,
            url: str,
        ) -> dict[str, Any]:
            assert url == VERSION_HREF
            return version_resource(
                code_locations=True
            )

        def paged_get(
            self,
            url: str,
        ) -> list[dict[str, Any]]:
            if url == CODE_LOCATIONS_HREF:
                return [
                    {
                        "_meta": {
                            "links": [
                                {
                                    "rel": "scan-summaries",
                                    "href": (
                                        SCAN_SUMMARIES_HREF
                                    ),
                                }
                            ]
                        }
                    }
                ]

            assert url == SCAN_SUMMARIES_HREF
            raise error

    with pytest.raises(
        BlackDuckCircuitOpenError,
    ):
        blackduck_scan.collect_version_evidence(
            Client(),
            project,
            version,
        )


def test_parallel_collection_propagates_circuit_and_context() -> None:
    project, _ = project_and_version()
    error = open_circuit_error()
    observed: dict[str, str] = {}

    class Client:
        def clone_for_worker(self) -> Client:
            return self

        def get(
            self,
            url: str,
        ) -> dict[str, Any]:
            del url
            observed.update(
                current_request_context()
            )
            raise error

    inventory = BlackDuckInventoryObservation(
        projects=(project,),
    )

    with pytest.raises(
        BlackDuckCircuitOpenError,
    ):
        blackduck_scan.collect_blackduck_scan_evidence(
            Client(),
            inventory,
            workers=1,
        )

    assert observed == {
        "project": "Example Project",
        "project_id": "project-id",
        "project_version": "1.0.0",
        "project_version_id": "version-id",
        "project_version_href": VERSION_HREF,
        "stage": "scm-direct-scan-evidence",
    }


def test_ordinary_scan_failure_remains_recorded() -> None:
    project, version = project_and_version()

    class Client:
        def get(
            self,
            url: str,
        ) -> dict[str, Any]:
            raise RuntimeError(
                f"ordinary failure: {url}"
            )

    result = blackduck_scan.collect_version_evidence(
        Client(),
        project,
        version,
    )

    assert result.version.scan_evidence_complete is False
    assert len(result.failures) == 1
    assert (
        result.failures[0].stage
        == "load-project-version-scan-evidence"
    )


def test_coverage_cli_does_not_publish_after_circuit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = open_circuit_error()
    published = False

    class Client:
        def __init__(
            self,
            *args: object,
            **kwargs: object,
        ) -> None:
            del args, kwargs

        def authenticate(self) -> None:
            return None

    def fail_coverage(
        *args: object,
        **kwargs: object,
    ) -> None:
        del args, kwargs
        raise error

    def forbidden_publish(
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal published
        del args, kwargs
        published = True
        raise AssertionError(
            "Coverage snapshot must not be published"
        )

    monkeypatch.setattr(
        coverage_cli,
        "BlackDuckClient",
        Client,
    )
    monkeypatch.setattr(
        coverage_cli,
        "execute_coverage",
        fail_coverage,
    )
    monkeypatch.setattr(
        coverage_cli,
        "write_coverage_snapshot",
        forbidden_publish,
    )

    args = argparse.Namespace(
        scm_snapshot=str(tmp_path),
        coverage_root=str(
            tmp_path / "coverage"
        ),
        snapshot_id=None,
        explicit_mappings=None,
        scan_evidence=None,
        collect_direct_scan_evidence=True,
        scan_evidence_workers=1,
        freshness_sla_days=30,
        retain_snapshots=10,
        provider_field="scm_provider",
        provider_instance_field=(
            "scm_provider_instance"
        ),
        repository_id_field=(
            "scm_repository_id"
        ),
        repository_url_field=(
            "scm_repository_url"
        ),
        bd_url="https://bd.example",
        api_token="token",
        project_name=None,
        project_name_contains=None,
        version_name=None,
        phase=None,
        max_projects=None,
        max_versions=None,
        workers=1,
        timeout=30,
        retries=0,
        retry_delay=0,
        page_limit=100,
        insecure=False,
        ca_bundle=None,
    )

    with pytest.raises(
        BlackDuckCircuitOpenError,
    ):
        coverage_cli.run(args)

    assert published is False
    assert not (
        tmp_path / "coverage"
    ).exists()
