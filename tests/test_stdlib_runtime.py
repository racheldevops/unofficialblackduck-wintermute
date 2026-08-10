from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src" / "wintermute"
ALLOWED_LOCAL_MODULES = {
    "__future__",
    "wintermute",
}


def production_python_files() -> list[Path]:
    return sorted(
        SOURCE_ROOT.rglob("*.py")
    )


def absolute_imports(
    path: Path,
) -> list[tuple[str, int]]:
    tree = ast.parse(
        path.read_text(encoding="utf-8"),
        filename=str(path),
    )
    imports: list[
        tuple[str, int]
    ] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(
                (
                    alias.name.partition(".")[0],
                    node.lineno,
                )
                for alias in node.names
            )
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module
        ):
            imports.append(
                (
                    node.module.partition(".")[0],
                    node.lineno,
                )
            )

    return imports


def project_configuration() -> dict[str, object]:
    return tomllib.loads(
        (ROOT / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )


def test_project_has_no_runtime_dependencies() -> None:
    configuration = project_configuration()

    assert configuration["project"][
        "dependencies"
    ] == []


def test_test_extra_contains_only_pytest() -> None:
    configuration = project_configuration()

    assert configuration["project"][
        "optional-dependencies"
    ]["test"] == [
        "pytest>=8,<9"
    ]


def test_wintermute_runtime_uses_only_standard_library() -> None:
    allowed = (
        set(sys.stdlib_module_names)
        | ALLOWED_LOCAL_MODULES
    )
    violations: list[str] = []

    for path in production_python_files():
        for module, line_number in absolute_imports(
            path
        ):
            if module not in allowed:
                violations.append(
                    f"{path.relative_to(ROOT)}:"
                    f"{line_number}: imports {module}"
                )

    assert not violations, (
        "Wintermute runtime contains "
        "non-standard imports:\n"
        + "\n".join(violations)
    )


def test_temporary_scm_source_tree_is_absent() -> None:
    assert not (
        SOURCE_ROOT / "scm_todelete"
    ).exists()
