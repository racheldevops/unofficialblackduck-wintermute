from __future__ import annotations

import ast
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (
        ROOT / path
    ).read_text(encoding="utf-8")


def workflow_template() -> str:
    return read(
        "deploy/cohort/workflow-template.yaml"
    )


def named_yaml_block(
    *,
    indentation: int,
    name: str,
    next_name: str,
) -> str:
    text = workflow_template()
    prefix = " " * indentation
    start_marker = (
        f"\n{prefix}- name: {name}\n"
    )
    end_marker = (
        f"\n{prefix}- name: {next_name}\n"
    )
    start = text.index(start_marker) + 1
    end = text.index(
        end_marker,
        start + len(start_marker),
    )

    return text[start:end]


def dag_task(
    name: str,
    next_name: str,
) -> str:
    return named_yaml_block(
        indentation=10,
        name=name,
        next_name=next_name,
    )


def template_block(
    name: str,
    next_name: str,
) -> str:
    return named_yaml_block(
        indentation=4,
        name=name,
        next_name=next_name,
    )


def scm_secret_python(
    workflow: str,
) -> str:
    marker = (
        "python - <<'PY' | "
        "kubectl apply --filename -"
    )
    marker_index = workflow.index(marker)
    source_start = workflow.index(
        "\n",
        marker_index,
    ) + 1
    source_end = workflow.index(
        "\n          PY",
        source_start,
    )

    return textwrap.dedent(
        workflow[source_start:source_end]
    )


def python_string_constants(
    source: str,
) -> set[str]:
    tree = ast.parse(source)

    return {
        node.value
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
        )
    }


def test_scm_image_is_built_and_published() -> None:
    workflow = read(
        ".github/workflows/"
        "cohort-container-build.yml"
    )

    assert "- target: scm" in workflow
    assert "image_suffix: scm" in workflow


def test_deployment_exposes_scm_mode() -> None:
    workflow = read(
        ".github/workflows/"
        "cohort-kubernetes-deploy.yml"
    )

    assert "scm_mode:" in workflow
    assert "- read-only" in workflow
    assert (
        '--scm-mode "${{ inputs.scm_mode }}"'
        in workflow
    )
    assert (
        "Apply scoped SCM credentials"
        in workflow
    )


def test_deployment_applies_scoped_scm_secret() -> None:
    workflow = read(
        ".github/workflows/"
        "cohort-kubernetes-deploy.yml"
    )
    source = scm_secret_python(workflow)
    constants = python_string_constants(source)

    assert (
        "blackduck-wintermute-scm-credentials"
        in constants
    )
    assert "GITHUB_ORG" in constants
    assert "GITHUB_TOKEN" in constants
    assert "SCM_GITHUB_ORG" in source
    assert "SCM_GITHUB_TOKEN" in source
    assert "stringData" in constants
    assert "--from-literal" not in workflow
    assert (
        "kubectl apply --filename -"
        in workflow
    )


def test_scm_secret_is_applied_before_preflight() -> None:
    workflow = read(
        ".github/workflows/"
        "cohort-kubernetes-deploy.yml"
    )

    secret_step = workflow.index(
        "- name: Apply scoped SCM credentials"
    )
    preflight_step = workflow.index(
        "- name: Validate cluster prerequisites"
    )

    assert secret_step < preflight_step


def test_scm_secret_apply_is_mode_scoped() -> None:
    workflow = read(
        ".github/workflows/"
        "cohort-kubernetes-deploy.yml"
    )

    assert (
        "inputs.operation == 'apply' "
        "&& inputs.scm_mode == 'read-only'"
        in workflow
    )


def test_scm_waits_for_source_to_finish() -> None:
    task = dag_task(
        "scm",
        "jira",
    )

    assert "depends: source.Succeeded" in task
    assert (
        "depends: validate-modes.Succeeded"
        not in task
    )
    assert (
        "workflow.parameters['scm-mode'] "
        "!= 'disabled'"
        in task
    )


def test_source_and_scm_blackduck_requests_are_not_parallel() -> None:
    source = dag_task(
        "source",
        "scm",
    )
    scm = dag_task(
        "scm",
        "jira",
    )

    assert (
        "depends: validate-modes.Succeeded"
        in source
    )
    assert "depends: source.Succeeded" in scm


def test_scm_uses_single_scm_path_segment() -> None:
    block = template_block(
        "scm",
        "jira",
    )

    assert (
        "          - --output-root\n"
        "          - /var/lib/blackduck-wintermute\n"
        in block
    )
    assert (
        "          - name: WINTERMUTE_OUTPUT_DIR\n"
        "            value: /var/lib/blackduck-wintermute\n"
        in block
    )
    assert (
        "mountPath: /var/lib/blackduck-wintermute/scm"
        in block
    )
    assert (
        "/var/lib/blackduck-wintermute/scm/scm"
        not in block
    )


def test_scm_task_uses_both_scoped_secrets() -> None:
    block = template_block(
        "scm",
        "jira",
    )

    assert (
        "name: blackduck-wintermute-"
        "blackduck-credentials"
        in block
    )
    assert (
        "name: blackduck-wintermute-"
        "scm-credentials"
        in block
    )
    assert (
        "command:\n"
        "          - blackduck-wintermute-scm-overview"
        in block
    )


def test_scm_is_disabled_by_default() -> None:
    cron = read(
        "deploy/cohort/cron-workflow.yaml"
    )
    customer = read(
        "deploy/overlays/customer-cohort/"
        "schedule-patch.yaml"
    )
    local = read(
        "deploy/overlays/docker-desktop-cohort/"
        "schedule-patch.yaml"
    )

    for text in (
        cron,
        customer,
        local,
    ):
        assert "name: scm-mode" in text
        assert "value: disabled" in text


def test_scm_has_isolated_persistent_storage() -> None:
    pvc = read("deploy/cohort/pvc.yaml")
    workflow = workflow_template()

    assert (
        "name: blackduck-wintermute-scm-data"
        in pvc
    )
    assert (
        "claimName: blackduck-wintermute-scm-data"
        in workflow
    )


def test_scm_blackduck_pacing_is_explicit() -> None:
    block = template_block(
        "scm",
        "jira",
    )

    assert (
        "WINTERMUTE_BLACKDUCK_REQUEST_INTERVAL_SECONDS"
        in block
    )
    assert (
        "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_THRESHOLD"
        in block
    )
    assert (
        "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_WINDOW_SECONDS"
        in block
    )


def test_scm_does_not_accept_apply_mode() -> None:
    renderer = read(
        "scripts/render_cohort_manifest.py"
    )
    helper = read(
        "scripts/local_cohort_k8s_helper.py"
    )
    renderer_modes = renderer.split(
        "SCM_MODES = {",
        1,
    )[1].split("}", 1)[0]
    helper_modes = helper.split(
        "SCM_MODES = {",
        1,
    )[1].split("}", 1)[0]

    assert '"read-only"' in renderer_modes
    assert '"read-only"' in helper_modes
    assert '"apply"' not in renderer_modes
    assert '"apply"' not in helper_modes


def test_scm_direct_scan_evidence_is_not_enabled_by_default() -> None:
    dockerfile = read("Dockerfile")
    workflow = workflow_template()
    scm_stage = dockerfile.split(
        "FROM runtime-base AS scm",
        1,
    )[1].split(
        "FROM runtime-base AS runtime",
        1,
    )[0]

    assert (
        "--collect-direct-scan-evidence"
        not in scm_stage
    )
    assert (
        "--collect-direct-scan-evidence"
        not in workflow
    )
