from __future__ import annotations

import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKER_FLAGS = (
    "--workers",
    "--parent-workers",
    "--rollup-workers",
)
KUBERNETES_ARGUMENT_FILES = (
    "deploy/base/cronjob.yaml",
    "deploy/overlays/customer/cronjob-patch.yaml",
    "deploy/overlays/customer/apply-mode-patch.yaml.example",
    "deploy/overlays/customer/customer-ca-patch.yaml.example",
    "deploy/examples/customer-ca-patch.example.yaml",
)


def argument_values(path: Path) -> list[str]:
    values: list[str] = []

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()

        if not stripped.startswith("- "):
            continue

        value = stripped[2:].strip().strip('"').strip("'")
        values.append(value)

    return values


def test_docker_default_uses_high_concurrency() -> None:
    text = (ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )
    runtime_stage = text.split(
        "FROM runtime-base AS runtime",
        1,
    )[1]
    command = next(
        line
        for line in runtime_stage.splitlines()
        if line.startswith("CMD ")
    )

    assert '"--resolve-bom-names"' in command

    for flag in WORKER_FLAGS:
        assert f'"{flag}", "8"' in command


@pytest.mark.parametrize("relative_path", KUBERNETES_ARGUMENT_FILES)
def test_kubernetes_arguments_use_high_concurrency(
    relative_path: str,
) -> None:
    values = argument_values(ROOT / relative_path)

    assert "--resolve-bom-names" in values

    for flag in WORKER_FLAGS:
        assert values.count(flag) == 1
        index = values.index(flag)
        assert values[index + 1] == "8"


@pytest.mark.parametrize(
    "relative_path",
    (
        "deploy/base/cronjob.yaml",
        "deploy/overlays/customer/cronjob-patch.yaml",
    ),
)
def test_kubernetes_resources_support_high_concurrency(
    relative_path: str,
) -> None:
    text = (ROOT / relative_path).read_text(encoding="utf-8")

    assert re.search(
        r"requests:\s+cpu:\s+\"1\"",
        text,
        re.MULTILINE,
    )
    assert re.search(
        r"limits:\s+cpu:\s+\"4\"",
        text,
        re.MULTILINE,
    )


@pytest.mark.parametrize(
    "relative_path",
    (
        "deploy/base/cronjob.yaml",
        "deploy/overlays/customer/cronjob-patch.yaml",
    ),
)
def test_kubernetes_memory_supports_eight_workers(
    relative_path: str,
) -> None:
    text = (ROOT / relative_path).read_text(
        encoding="utf-8"
    )

    assert re.search(
        r"requests:\s+cpu:\s+\"1\"\s+memory:\s+1Gi",
        text,
        re.MULTILINE,
    )
    assert re.search(
        r"limits:\s+cpu:\s+\"4\"\s+memory:\s+4Gi",
        text,
        re.MULTILINE,
    )
