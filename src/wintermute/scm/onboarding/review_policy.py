from __future__ import annotations

import re
from typing import Any


EVIDENCE_FRAGMENT = re.compile(
    r"^ev-[0-9a-f]{8,}"
    r"[\]\).,;:]*$",
    re.IGNORECASE,
)

ADVISORY_CONFLICT_PATTERNS = (
    re.compile(
        r"^Invalid project-name strategy "
        r"was ignored$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^Invalid boolean parameter "
        r"was ignored:",
        re.IGNORECASE,
    ),
    re.compile(
        r"^Unsupported profile parameter "
        r"was ignored:",
        re.IGNORECASE,
    ),
    re.compile(
        r"^Unsupported build-system label "
        r"normalized to generic:",
        re.IGNORECASE,
    ),
)

BLOCKING_PATTERNS = (
    re.compile(
        r"\b(?:no longer valid|deprecated|"
        r"moved elsewhere|successor repository|"
        r"combined elsewhere)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:should scanning continue|"
        r"intended scan target|"
        r"actual scan target)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:credential-protected|"
        r"credential value|"
        r"required external configuration|"
        r"runtime-selected from external)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:no language classification|"
        r"encrypted.*configuration)\b",
        re.IGNORECASE,
    ),
)

ADVISORY_QUESTION_PATTERNS = (
    re.compile(
        r"\b(?:exact .* version|"
        r"exact .* parameter|"
        r"built container image|"
        r"image artifact|"
        r"dependency inventory)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:not supplied|"
        r"not provided|"
        r"cannot be confirmed|"
        r"not fully confirmed|"
        r"appears limited)\b",
        re.IGNORECASE,
    ),
)


def compact_issue(value: Any) -> str:
    selected = re.sub(
        r"\s+",
        " ",
        str(value or ""),
    ).strip()

    return selected[:2000]


def evidence_only(value: str) -> bool:
    selected = value.strip()

    if EVIDENCE_FRAGMENT.fullmatch(
        selected
    ):
        return True

    return selected.casefold() in {
        "evidence_ids",
        "question",
        "summary",
        "jenkins",
        "dockerfile",
        "gemfile",
        "build.gradle",
        "settings.gradle",
        "package.json",
        "pom.xml",
        "composer.json",
        "go.mod",
        "maven",
        "npm",
        "binary_scan",
        "buildless",
        "package manager",
    }


def matches_any(
    value: str,
    patterns: tuple[
        re.Pattern[str],
        ...
    ],
) -> bool:
    return any(
        pattern.search(value)
        for pattern in patterns
    )


def classify_conflict(
    value: str,
) -> str:
    if evidence_only(value):
        return "advisory"

    if matches_any(
        value,
        BLOCKING_PATTERNS,
    ):
        return "blocking"

    if matches_any(
        value,
        ADVISORY_CONFLICT_PATTERNS,
    ):
        return "advisory"

    if value.casefold().startswith(
        "unsupported value normalized "
        "to unknown:"
    ):
        return "blocking"

    return "blocking"


def classify_question(
    value: str,
) -> str:
    if evidence_only(value):
        return "advisory"

    if matches_any(
        value,
        BLOCKING_PATTERNS,
    ):
        return "blocking"

    if matches_any(
        value,
        ADVISORY_QUESTION_PATTERNS,
    ):
        return "advisory"

    return "advisory"


def classify_profile_issues(
    profile: dict[str, Any],
) -> dict[str, list[str]]:
    blocking_conflicts: list[str] = []
    advisory_conflicts: list[str] = []
    blocking_questions: list[str] = []
    advisory_questions: list[str] = []

    for raw_value in profile.get(
        "conflicts",
        [],
    ):
        value = compact_issue(raw_value)

        if not value:
            continue

        if classify_conflict(value) == (
            "blocking"
        ):
            blocking_conflicts.append(value)
        else:
            advisory_conflicts.append(value)

    for raw_value in profile.get(
        "unresolved_questions",
        [],
    ):
        value = compact_issue(raw_value)

        if not value:
            continue

        if classify_question(value) == (
            "blocking"
        ):
            blocking_questions.append(value)
        else:
            advisory_questions.append(value)

    return {
        "blocking_conflicts": sorted(
            set(blocking_conflicts)
        ),
        "advisory_conflicts": sorted(
            set(advisory_conflicts)
        ),
        "blocking_questions": sorted(
            set(blocking_questions)
        ),
        "advisory_questions": sorted(
            set(advisory_questions)
        ),
    }
