from __future__ import annotations

from pathlib import Path

from wintermute.scm.onboarding.central_bundle import (
    CentralBundleConfiguration,
    render_bundle,
)
from wintermute.scm.onboarding.template_artifacts import (
    LoadedTemplatePlan,
)


def template_plan(
    tmp_path: Path,
) -> LoadedTemplatePlan:
    return LoadedTemplatePlan(
        directory=tmp_path,
        plan={
            "plan_id": "template-plan",
        },
        catalog={},
        contracts={
            "contracts": [
                {
                    "scan_contract_id": (
                        "scan-python"
                    ),
                    "contract": {
                        "schema_version": 1,
                        "template_id": (
                            "python-security-scan"
                        ),
                        "template_version": 1,
                        "engine": "bridge",
                        "products": [
                            "blackduck-sca"
                        ],
                        "scan_mode": "detector",
                        "resource_class": "medium",
                        "timeout_seconds": 3600,
                        "runtime_parameters": {
                            "binary_scan": False,
                            "buildless": True,
                            "detector_search_depth": 3,
                            "project_name_strategy": (
                                "provider-id"
                            ),
                        },
                        "contract_digest": (
                            "sha256:" + "a" * 64
                        ),
                    },
                }
            ]
        },
        assignments={
            "assignments": [
                {
                    "provider": "github",
                    "provider_instance": (
                        "api.github.com"
                    ),
                    "repository_id": "101",
                    "scan_contract_id": (
                        "scan-python"
                    ),
                    "onboarding_policy": (
                        "required"
                    ),
                },
                {
                    "provider": "gitlab",
                    "provider_instance": (
                        "gitlab.example"
                    ),
                    "repository_id": "202",
                    "scan_contract_id": (
                        "scan-python"
                    ),
                    "onboarding_policy": (
                        "required"
                    ),
                },
                {
                    "provider": "gitlab",
                    "provider_instance": (
                        "gitlab.example"
                    ),
                    "repository_id": "203",
                    "scan_contract_id": (
                        "scan-python"
                    ),
                    "onboarding_policy": (
                        "review"
                    ),
                },
            ]
        },
        digest="sha256:" + "b" * 64,
    )


def test_bundle_has_one_template_per_provider(
    tmp_path: Path,
) -> None:
    registry, github, gitlab = (
        render_bundle(
            template_plan(tmp_path),
            CentralBundleConfiguration(
                image=(
                    "registry.example/"
                    "wintermute-scan@sha256:"
                    + "c" * 64
                ),
                bridge_sha256="d" * 64,
                github_repository=(
                    "acme/wintermute-security-scans"
                ),
                github_ref="main",
                github_checkout_action_sha=(
                    "e" * 40
                ),
                gitlab_project=(
                    "group/wintermute-security-scans"
                ),
                gitlab_ref="main",
            ),
        )
    )

    assert len(
        registry["contracts"]
    ) == 1
    assert len(
        registry["assignments"]
    ) == 2
    assert github is not None
    assert gitlab is not None
    assert github.count(
        "Wintermute Security Scan"
    ) == 1
    assert gitlab.count(
        "wintermute_security_scan:"
    ) == 1
    assert "synopsys" not in (
        github + gitlab
    ).casefold()
