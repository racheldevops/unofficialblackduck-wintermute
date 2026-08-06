#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
from pathlib import Path


SENSITIVE_KEYS = (
    "BLACKDUCK_API_TOKEN",
    "JIRA_API_TOKEN",
    "JIRA_PAT",
    "DATADOG_API_KEY",
    "REGISTRY_PASSWORD",
    "KUBE_CONFIG_B64",
    "GITGUARDIAN_API_KEY",
)

TEXT_SUFFIXES = {
    ".md",
    ".yaml",
    ".yml",
    ".json",
    ".sh",
    ".zsh",
}


def tracked_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        stdout=subprocess.PIPE,
        check=True,
    )

    return [
        Path(value.decode("utf-8"))
        for value in completed.stdout.split(b"\0")
        if value
    ]


def eligible(path: Path) -> bool:
    if path == Path("README.md"):
        return True

    if path.parts and path.parts[0] == "READMEs":
        return True

    if (
        path.parts
        and path.parts[0] == "deploy"
        and "example" in path.name.lower()
    ):
        return True

    return False


def sanitize_key(text: str, key: str) -> str:
    yaml_pattern = re.compile(
        rf"(?m)^(\s*{re.escape(key)}\s*:\s*)"
        rf"([^#\n]*)(\s*(?:#.*)?)$"
    )

    def yaml_replace(match: re.Match[str]) -> str:
        value = match.group(2).strip()

        if value in {"", '""', "''", "null", "~"}:
            return match.group(0)

        if value.startswith(("$", "${{")):
            return match.group(0)

        return (
            f'{match.group(1)}""'
            f"{match.group(3)}"
        )

    text = yaml_pattern.sub(yaml_replace, text)

    json_pattern = re.compile(
        rf'(?m)^(\s*"{re.escape(key)}"\s*:\s*)'
        rf'(.+?)(,?)(\s*)$'
    )

    def json_replace(match: re.Match[str]) -> str:
        value = match.group(2).strip()

        if value in {'""', "null"}:
            return match.group(0)

        return (
            f'{match.group(1)}""'
            f"{match.group(3)}"
            f"{match.group(4)}"
        )

    text = json_pattern.sub(json_replace, text)

    assignment_pattern = re.compile(
        rf"\b{re.escape(key)}="
        rf'(?:"[^"\n]*"|\'[^\'\n]*\'|'
        rf'(?!\$)[^\s\\]+)'
    )
    text = assignment_pattern.sub(
        f'{key}=""',
        text,
    )

    return text


def sanitize(path: Path) -> bool:
    if (
        not path.is_file()
        or path.suffix.lower() not in TEXT_SUFFIXES
        or not eligible(path)
    ):
        return False

    original = path.read_text(encoding="utf-8")
    updated = original

    for key in SENSITIVE_KEYS:
        updated = sanitize_key(updated, key)

    if "registry-secret" in path.name.lower():
        updated = re.sub(
            r"(?m)^(\s*\.dockerconfigjson\s*:\s*).*$",
            r'\1""',
            updated,
        )

    if updated == original:
        return False

    path.write_text(updated, encoding="utf-8")
    return True


def main() -> int:
    changed = [
        str(path)
        for path in tracked_files()
        if sanitize(path)
    ]

    for path in changed:
        print(f"Sanitized {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
