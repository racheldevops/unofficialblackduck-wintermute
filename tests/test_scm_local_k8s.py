from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "scripts"
    / "run_local_scm_k8s.zsh"
)


def test_local_scm_kubernetes_is_read_only_and_suspended() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "kind: CronJob" in text
    assert "suspend: true" in text
    assert "imagePullPolicy: Never" in text
    assert "--allow-partial" in text
    assert "--insecure" in text
    assert (
        "--collect-direct-scan-evidence"
        not in text
    )
    assert (
        "automountServiceAccountToken: false"
        in text
    )
    assert "readOnlyRootFilesystem: true" in text

    for forbidden in (
        "kind: Workflow",
        "kind: CronWorkflow",
        "--apply",
    ):
        assert forbidden not in text
