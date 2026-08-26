from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = (
    ROOT
    / "deploy"
    / "overlays"
    / "docker-desktop-cohort"
)


def test_local_overlay_installs_insecure_patch() -> None:
    kustomization = (
        OVERLAY / "kustomization.yaml"
    ).read_text(encoding="utf-8")

    assert (
        "path: insecure-network-patch.json"
        in kustomization
    )
    assert "kind: WorkflowTemplate" in kustomization
    assert (
        "name: blackduck-wintermute-cohort"
        in kustomization
    )


def test_local_insecure_patch_targets_source_and_scm() -> None:
    operations = json.loads(
        (
            OVERLAY
            / "insecure-network-patch.json"
        ).read_text(encoding="utf-8")
    )

    assert operations == [
        {
            "op": "test",
            "path": "/spec/templates/2/name",
            "value": "source",
        },
        {
            "op": "add",
            "path": (
                "/spec/templates/2/"
                "container/args/-"
            ),
            "value": "--insecure",
        },
        {
            "op": "test",
            "path": "/spec/templates/3/name",
            "value": "scm",
        },
        {
            "op": "add",
            "path": (
                "/spec/templates/3/"
                "container/args/-"
            ),
            "value": "--insecure",
        },
    ]
