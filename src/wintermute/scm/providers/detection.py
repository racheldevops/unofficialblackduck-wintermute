from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class ScmProviderSelection:
    provider: str
    url: str


def normalized_url(value: str) -> str:
    selected = str(value or "").strip()
    parsed = urlsplit(selected)

    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "SCM URL must be HTTPS without credentials, "
            "query, or fragment"
        )

    return urlunsplit(
        (
            "https",
            parsed.netloc.casefold(),
            parsed.path.rstrip("/"),
            "",
            "",
        )
    )


def provider_from_url(value: str) -> str:
    selected = normalized_url(value)
    parsed = urlsplit(selected)
    host = parsed.netloc.casefold()
    path = parsed.path.casefold()

    if (
        "gitlab" in host
        or path == "/api/v4"
        or path.endswith("/api/v4")
    ):
        return "gitlab"

    if (
        "github" in host
        or "graphql" in path
        or path.endswith("/api/v3")
    ):
        return "github"

    raise ValueError(
        "Could not determine SCM provider from URL"
    )


def gitlab_rest_url(value: str) -> str:
    selected = normalized_url(value)
    parsed = urlsplit(selected)
    path = parsed.path.rstrip("/")
    marker = "/api/v4"

    if marker in path:
        path = path.split(marker, 1)[0] + marker
    else:
        path = marker

    return urlunsplit(
        (
            "https",
            parsed.netloc,
            path,
            "",
            "",
        )
    )


def gitlab_group_from_url(value: str) -> str:
    selected = normalized_url(value)
    parsed = urlsplit(selected)
    path = parsed.path.strip("/")

    if not path or path.startswith("api/"):
        return ""

    parts = [
        part
        for part in path.split("/")
        if part
    ]

    if parts and parts[-1].endswith(".git"):
        parts[-1] = parts[-1][:-4]

    if len(parts) < 2:
        return ""

    return "/".join(parts[:-1])


def select_provider(
    scm_url: str,
    *,
    gitlab_group: str = "",
    gitlab_rest_base_url: str = "",
    github_graphql_url: str = "",
) -> ScmProviderSelection:
    if str(scm_url or "").strip():
        selected = normalized_url(scm_url)

        return ScmProviderSelection(
            provider=provider_from_url(selected),
            url=selected,
        )

    if (
        str(gitlab_rest_base_url or "").strip()
        or str(gitlab_group or "").strip()
    ):
        selected = (
            gitlab_rest_base_url
            or "https://gitlab.com/api/v4"
        )

        return ScmProviderSelection(
            provider="gitlab",
            url=normalized_url(selected),
        )

    selected = (
        github_graphql_url
        or "https://api.github.com/graphql"
    )

    return ScmProviderSelection(
        provider="github",
        url=normalized_url(selected),
    )
