from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from wintermute.blackduck.resources import to_float


class ScoreOperator(str, Enum):
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"


@dataclass(frozen=True)
class CollectionCriteria:
    score_field: str = "overallScore"
    score_operator: ScoreOperator = (
        ScoreOperator.GREATER_THAN_OR_EQUAL
    )
    threshold: float = 7.0
    require_exploit_available: bool = False
    require_reachable: bool = False
    reachability_mode: str = "none"
    policy_name: str = ""
    policy_rule_id: str = ""
    skip_policy_rules: bool = False
    include_policy_rule_details: bool = False
    entity_custom_field: str = ""
    require_entity: bool = False

    def __post_init__(self) -> None:
        operator = self.score_operator

        if not isinstance(operator, ScoreOperator):
            operator = ScoreOperator(str(operator))
            object.__setattr__(
                self,
                "score_operator",
                operator,
            )

        object.__setattr__(
            self,
            "score_field",
            str(
                self.score_field or "overallScore"
            ).strip(),
        )
        object.__setattr__(
            self,
            "threshold",
            float(self.threshold),
        )
        object.__setattr__(
            self,
            "policy_name",
            str(self.policy_name or "").strip(),
        )
        object.__setattr__(
            self,
            "policy_rule_id",
            str(self.policy_rule_id or "").strip(),
        )
        object.__setattr__(
            self,
            "entity_custom_field",
            str(
                self.entity_custom_field or ""
            ).strip(),
        )

        if not self.score_field:
            raise ValueError(
                "score_field must not be empty"
            )

        if self.reachability_mode not in {
            "none",
            "field",
            "ai",
        }:
            raise ValueError(
                "reachability_mode must be none, "
                "field, or ai"
            )

        if (
            self.skip_policy_rules
            and (
                self.policy_name
                or self.policy_rule_id
            )
        ):
            raise ValueError(
                "skip_policy_rules cannot be used "
                "with policy filters"
            )

        if (
            self.require_entity
            and not self.entity_custom_field
        ):
            raise ValueError(
                "require_entity requires "
                "entity_custom_field"
            )

    def score_passes(self, value: Any) -> bool:
        score = to_float(value)

        if score is None:
            return False

        if (
            self.score_operator
            == ScoreOperator.GREATER_THAN
        ):
            return score > self.threshold

        return score >= self.threshold


def jira_parent_rollup_criteria(
    *,
    threshold: float = 7.0,
    score_field: str = "overallScore",
    entity_custom_field: str = "foo Entity",
    require_entity: bool = False,
) -> CollectionCriteria:
    return CollectionCriteria(
        score_field=score_field,
        score_operator=(
            ScoreOperator.GREATER_THAN_OR_EQUAL
        ),
        threshold=threshold,
        entity_custom_field=entity_custom_field,
        require_entity=require_entity,
    )


def datadog_high_risk_criteria(
    *,
    threshold: float = 8.9,
    score_field: str = "overallScore",
    require_exploit_available: bool = True,
    require_reachable: bool = False,
    reachability_mode: str = "none",
    policy_name: str = "",
    policy_rule_id: str = "",
    skip_policy_rules: bool = False,
    include_policy_rule_details: bool = False,
) -> CollectionCriteria:
    return CollectionCriteria(
        score_field=score_field,
        score_operator=ScoreOperator.GREATER_THAN,
        threshold=threshold,
        require_exploit_available=(
            require_exploit_available
        ),
        require_reachable=require_reachable,
        reachability_mode=reachability_mode,
        policy_name=policy_name,
        policy_rule_id=policy_rule_id,
        skip_policy_rules=skip_policy_rules,
        include_policy_rule_details=(
            include_policy_rule_details
        ),
    )
