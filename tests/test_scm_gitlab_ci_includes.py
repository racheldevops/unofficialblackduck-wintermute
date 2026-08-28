from wintermute.scm.providers.gitlab.observations import (
    local_includes,
)


def test_local_ci_includes_are_found() -> None:
    payload = """
include:
  - local: .gitlab/blackduck.yml
  - ".gitlab/build.yml"
  - project: shared/ci
    ref: main
    file:
      - artifactory-publish.yml

build:
  script: echo build
"""

    assert local_includes(payload) == (
        ".gitlab/blackduck.yml",
        ".gitlab/build.yml",
    )


def test_scalar_ci_include_is_found() -> None:
    assert local_includes(
        'include: ".gitlab/scan.yml"\n'
    ) == (
        ".gitlab/scan.yml",
    )


def test_remote_ci_include_is_ignored() -> None:
    assert local_includes(
        'include: "https://example.invalid/ci.yml"\n'
    ) == ()
