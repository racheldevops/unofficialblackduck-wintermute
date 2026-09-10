from wintermute.scm.onboarding.review_policy import (
    classify_profile_issues,
)


def test_normalization_warnings_are_advisory() -> None:
    result = classify_profile_issues(
        {
            "conflicts": [
                (
                    "Invalid project-name strategy "
                    "was ignored"
                ),
                (
                    "Unsupported profile parameter "
                    "was ignored: publishing"
                ),
            ],
            "unresolved_questions": [
                (
                    "Exact dependency configuration "
                    "cannot be confirmed"
                )
            ],
        }
    )

    assert result[
        "blocking_conflicts"
    ] == []
    assert len(
        result["advisory_conflicts"]
    ) == 2
    assert len(
        result["advisory_questions"]
    ) == 1


def test_deprecated_repository_is_blocking() -> None:
    result = classify_profile_issues(
        {
            "conflicts": [],
            "unresolved_questions": [
                (
                    "The repository is deprecated; "
                    "confirm the successor repository"
                )
            ],
        }
    )

    assert len(
        result["blocking_questions"]
    ) == 1


def test_unknown_conflict_fails_closed() -> None:
    result = classify_profile_issues(
        {
            "conflicts": [
                "Ambiguous build system"
            ],
            "unresolved_questions": [],
        }
    )

    assert result[
        "blocking_conflicts"
    ] == [
        "Ambiguous build system"
    ]
