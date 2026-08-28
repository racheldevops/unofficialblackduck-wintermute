from wintermute.scm.providers.detection import (
    gitlab_group_from_url,
    gitlab_rest_url,
    provider_from_url,
)


def test_detects_self_managed_gitlab() -> None:
    assert provider_from_url(
        "https://gitlab.example.invalid/group/repo"
    ) == "gitlab"
    assert gitlab_rest_url(
        "https://gitlab.example.invalid/group/repo"
    ) == (
        "https://gitlab.example.invalid/api/v4"
    )
    assert gitlab_group_from_url(
        (
            "https://gitlab.example.invalid/"
            "group/subgroup/repository.git"
        )
    ) == "group/subgroup"


def test_detects_github_by_graphql_url() -> None:
    assert provider_from_url(
        "https://source.example.invalid/api/graphql"
    ) == "github"
