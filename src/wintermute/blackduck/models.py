from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from wintermute.blackduck.resources import (
    canonical_href,
    sha256_hex,
)


def stable_key(parts: list[str]) -> str:
    return json.dumps(
        [str(part or "") for part in parts],
        ensure_ascii=False,
        separators=(",", ":"),
    )


@dataclass(frozen=True)
class ProjectVersionRef:
    instance_url: str
    project: str
    version: str
    project_href: str = ""
    version_href: str = ""
    phase: str = ""
    updated: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "instance_url",
            canonical_href(self.instance_url),
        )
        object.__setattr__(
            self,
            "project_href",
            canonical_href(self.project_href),
        )
        object.__setattr__(
            self,
            "version_href",
            canonical_href(self.version_href),
        )

    @property
    def identity_key(self) -> str:
        if self.version_href:
            return self.version_href

        return stable_key(
            [
                self.instance_url,
                self.project,
                self.version,
            ]
        )

    @property
    def external_id(self) -> str:
        return sha256_hex(
            f"project-version|{self.identity_key}"
        )


@dataclass(frozen=True)
class LineageContext:
    parent: ProjectVersionRef
    child: ProjectVersionRef
    detection_method: str = ""
    bom_component_name: str = ""
    bom_component_version: str = ""

    @property
    def relationship_key(self) -> str:
        return stable_key(
            [
                self.parent.identity_key,
                self.child.identity_key,
            ]
        )

    @property
    def external_id(self) -> str:
        return sha256_hex(
            f"lineage|{self.relationship_key}"
        )


@dataclass(frozen=True)
class CollectionTarget:
    project_version: ProjectVersionRef
    lineage_contexts: tuple[LineageContext, ...] = ()

    def with_contexts(
        self,
        contexts: list[LineageContext],
    ) -> CollectionTarget:
        unique = {
            context.external_id: context
            for context in (
                list(self.lineage_contexts) + contexts
            )
        }

        return CollectionTarget(
            project_version=self.project_version,
            lineage_contexts=tuple(
                unique[key]
                for key in sorted(unique)
            ),
        )


@dataclass(frozen=True)
class NormalizedFinding:
    project_version: ProjectVersionRef
    component: str
    component_version: str
    vulnerability: str
    severity: str = ""
    score_field: str = "overallScore"
    score: float | None = None
    component_href: str = ""
    vulnerability_href: str = ""
    cvss_vector: str = ""
    exploit_available: bool = False
    exploitable: str = ""
    reachable: bool = False
    reachability: str = ""
    reachability_source: str = ""
    policy_name: str = ""
    policy_rule_href: str = ""
    entity: str = ""
    lineage_contexts: tuple[LineageContext, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "component_href",
            canonical_href(self.component_href),
        )
        object.__setattr__(
            self,
            "vulnerability_href",
            canonical_href(self.vulnerability_href),
        )
        object.__setattr__(
            self,
            "severity",
            str(self.severity or "").strip().upper(),
        )

    @property
    def finding_key(self) -> str:
        component_identity = (
            self.component_href
            or stable_key(
                [
                    self.component,
                    self.component_version,
                ]
            )
        )

        return stable_key(
            [
                self.project_version.identity_key,
                component_identity,
                self.vulnerability or "UNKNOWN",
            ]
        )

    @property
    def external_id(self) -> str:
        return sha256_hex(
            f"finding|{self.finding_key}"
        )
