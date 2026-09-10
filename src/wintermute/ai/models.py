from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any


def canonical_json_bytes(
    value: Any,
) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def stable_digest(
    value: Any,
) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            canonical_json_bytes(value)
        ).hexdigest()
    )


def estimated_tokens(
    value: str,
) -> int:
    size = len(
        str(value).encode("utf-8")
    )

    return max(
        1,
        math.ceil(size / 3),
    )


@dataclass(frozen=True)
class ModelUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    reasoning_tokens: int = 0

    def __post_init__(self) -> None:
        for field in (
            "input_tokens",
            "output_tokens",
            "cached_input_tokens",
            "reasoning_tokens",
        ):
            value = getattr(self, field)

            if (
                type(value) is not int
                or value < 0
            ):
                raise ValueError(
                    f"{field} must be a "
                    "nonnegative integer"
                )

    @property
    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_input_tokens": (
                self.cached_input_tokens
            ),
            "reasoning_tokens": (
                self.reasoning_tokens
            ),
            "total_tokens": self.total_tokens,
        }

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
    ) -> ModelUsage:
        return cls(
            input_tokens=int(
                value.get("input_tokens") or 0
            ),
            output_tokens=int(
                value.get("output_tokens") or 0
            ),
            cached_input_tokens=int(
                value.get(
                    "cached_input_tokens"
                )
                or 0
            ),
            reasoning_tokens=int(
                value.get("reasoning_tokens")
                or 0
            ),
        )


@dataclass(frozen=True)
class ModelResponse:
    content: str
    usage: ModelUsage
    request_id: str = ""

    def __post_init__(self) -> None:
        if not self.content.strip():
            raise ValueError(
                "Model response content is empty"
            )


@dataclass(frozen=True)
class EvidenceDescriptor:
    evidence_id: str
    relative_path: str
    safe_path: str
    kind: str
    digest: str
    byte_count: int
    truncated: bool
    relevance: float
    keywords: tuple[str, ...]

    def as_dict(
        self,
        *,
        include_private_path: bool = False,
    ) -> dict[str, Any]:
        result = {
            "evidence_id": self.evidence_id,
            "safe_path": self.safe_path,
            "kind": self.kind,
            "digest": self.digest,
            "byte_count": self.byte_count,
            "truncated": self.truncated,
            "relevance": round(
                self.relevance,
                4,
            ),
            "keywords": list(self.keywords),
        }

        if include_private_path:
            result["relative_path"] = (
                self.relative_path
            )

        return result


@dataclass(frozen=True)
class AnalysisRound:
    round_number: int
    request_digest: str
    cache_hit: bool
    requested_evidence_ids: tuple[
        str,
        ...
    ]
    usage: ModelUsage
    estimated_cost_usd: float
    latency_seconds: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "round_number": (
                self.round_number
            ),
            "request_digest": (
                self.request_digest
            ),
            "cache_hit": self.cache_hit,
            "requested_evidence_ids": list(
                self.requested_evidence_ids
            ),
            "usage": self.usage.as_dict(),
            "estimated_cost_usd": round(
                self.estimated_cost_usd,
                8,
            ),
            "latency_seconds": round(
                self.latency_seconds,
                3,
            ),
        }


@dataclass(frozen=True)
class AnalysisResult:
    analysis_id: str
    task: str
    task_version: str
    provider: str
    model: str
    input_digest: str
    result: dict[str, Any]
    evidence_ids: tuple[str, ...]
    rounds: tuple[AnalysisRound, ...]
    created_at: str

    @property
    def usage(self) -> ModelUsage:
        return ModelUsage(
            input_tokens=sum(
                value.usage.input_tokens
                for value in self.rounds
            ),
            output_tokens=sum(
                value.usage.output_tokens
                for value in self.rounds
            ),
            cached_input_tokens=sum(
                value.usage.cached_input_tokens
                for value in self.rounds
            ),
            reasoning_tokens=sum(
                value.usage.reasoning_tokens
                for value in self.rounds
            ),
        )

    @property
    def estimated_cost_usd(self) -> float:
        return sum(
            value.estimated_cost_usd
            for value in self.rounds
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "task": self.task,
            "task_version": self.task_version,
            "provider": self.provider,
            "model": self.model,
            "input_digest": self.input_digest,
            "result": self.result,
            "evidence_ids": list(
                self.evidence_ids
            ),
            "rounds": [
                value.as_dict()
                for value in self.rounds
            ],
            "usage": self.usage.as_dict(),
            "estimated_cost_usd": round(
                self.estimated_cost_usd,
                8,
            ),
            "created_at": self.created_at,
        }
