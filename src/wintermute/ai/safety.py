from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit


_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?"
    r"-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_EMAIL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
_URL_RE = re.compile(
    r"https?://[^\s'\"<>]+",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?im)^(\s*"""
    r"""(?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|"""
    r"""API_KEY|PRIVATE_KEY|CONNECTION_STRING|CREDENTIAL)"""
    r"""[A-Z0-9_]*"""
    r"""|password|token|secret|api[_-]?key)"""
    r"""\s*[:=]\s*)(.+)$"""
)
_KNOWN_TOKEN_RE = re.compile(
    r"\b(?:ghp|github_pat|glpat|sk)-"
    r"[A-Za-z0-9_-]{16,}\b",
    re.IGNORECASE,
)
_HIGH_ENTROPY_RE = re.compile(
    r"\b[A-Za-z0-9+/=_-]{32,}\b"
)
_PROMPT_INJECTION_RE = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?previous\s+instructions|"
    r"system\s+prompt|developer\s+message|"
    r"reveal\s+(?:the\s+)?secret|"
    r"act\s+as\s+(?:an?\s+)?(?:assistant|system))"
)

_PRESERVED_NAMES = {
    ".github",
    ".gitlab",
    "workflows",
    "ci",
    "config",
    "scripts",
    "src",
    "test",
    "tests",
    "build",
    "gradle",
    "maven",
    "docker",
    "charts",
    "templates",
}

_PRESERVED_FILES = {
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "requirements-dev.txt",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradle.properties",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "composer.json",
    "gemfile",
    "gemfile.lock",
    "dockerfile",
    "makefile",
    ".gitlab-ci.yml",
}


class Anonymizer:
    def __init__(
        self,
        key: str,
    ) -> None:
        self.key = (
            str(key or "local-only")
            .encode("utf-8")
        )

    def alias(
        self,
        category: str,
        value: str,
    ) -> str:
        normalized = str(value or "").strip()

        if not normalized:
            return ""

        digest = hmac.new(
            self.key,
            (
                f"{category}|{normalized}"
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:12]

        return f"{category}-{digest}"

    def safe_path(
        self,
        value: str,
    ) -> str:
        path = PurePosixPath(
            str(value).replace("\\", "/")
        )
        rendered: list[str] = []

        for part in path.parts:
            lowered = part.casefold()

            if (
                lowered in _PRESERVED_NAMES
                or lowered in _PRESERVED_FILES
            ):
                rendered.append(part)
                continue

            suffix = PurePosixPath(part).suffix

            if suffix:
                rendered.append(
                    self.alias(
                        "path",
                        part,
                    )
                    + suffix.casefold()
                )
            else:
                rendered.append(
                    self.alias(
                        "path",
                        part,
                    )
                )

        return "/".join(rendered)


class Sanitizer:
    def __init__(
        self,
        anonymizer: Anonymizer,
    ) -> None:
        self.anonymizer = anonymizer

    def sanitize_text(
        self,
        value: str,
    ) -> str:
        selected = str(value)
        selected = _PRIVATE_KEY_RE.sub(
            "[PRIVATE_KEY_REMOVED]",
            selected,
        )
        selected = _BEARER_RE.sub(
            "Bearer [REDACTED]",
            selected,
        )
        selected = _KNOWN_TOKEN_RE.sub(
            "[TOKEN_REDACTED]",
            selected,
        )
        selected = _SECRET_ASSIGNMENT_RE.sub(
            lambda match: (
                match.group(1)
                + "[REDACTED]"
            ),
            selected,
        )
        selected = _EMAIL_RE.sub(
            lambda match: (
                "<email:"
                + self.anonymizer.alias(
                    "identity",
                    match.group(0),
                )
                + ">"
            ),
            selected,
        )
        selected = _URL_RE.sub(
            self._sanitize_url,
            selected,
        )

        lines: list[str] = []

        for line in selected.splitlines():
            if _PROMPT_INJECTION_RE.search(line):
                lines.append(
                    "[UNTRUSTED_DIRECTIVE_REMOVED]"
                )
                continue

            lines.append(
                _HIGH_ENTROPY_RE.sub(
                    self._redact_entropy,
                    line,
                )
            )

        return "\n".join(lines)

    def _sanitize_url(
        self,
        match: re.Match[str],
    ) -> str:
        value = match.group(0)
        parsed = urlsplit(value)
        host = parsed.hostname or ""

        return (
            "<url:"
            + self.anonymizer.alias(
                "host",
                host,
            )
            + ">"
        )

    @staticmethod
    def _redact_entropy(
        match: re.Match[str],
    ) -> str:
        value = match.group(0)

        if re.fullmatch(
            r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}",
            value,
        ):
            return value.casefold()

        if (
            value.isalpha()
            or value.isdigit()
        ):
            return value

        return "[HIGH_ENTROPY_REDACTED]"
