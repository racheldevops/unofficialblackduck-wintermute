from pathlib import Path

from wintermute.scm.providers.gitlab.cache import (
    GitLabCapabilityCache,
)


def test_denial_cache_round_trip(
    tmp_path: Path,
) -> None:
    path = tmp_path / "capabilities.json"
    cache = GitLabCapabilityCache(
        path,
        provider_instance=(
            "gitlab.example.invalid"
        ),
    )
    cache.record_denied(
        "20",
        "pipelines",
        "403 Forbidden",
    )
    cache.save()

    loaded = GitLabCapabilityCache(
        path,
        provider_instance=(
            "gitlab.example.invalid"
        ),
    )

    assert loaded.denied(
        "20",
        "pipelines",
    ) == "403 Forbidden"

    loaded.clear(
        "20",
        "pipelines",
    )
    loaded.save()

    assert loaded.denied(
        "20",
        "pipelines",
    ) == ""
