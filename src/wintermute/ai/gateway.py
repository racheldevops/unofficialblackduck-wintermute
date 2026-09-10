from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from wintermute.ai.config import (
    AISettings,
)
from wintermute.ai.models import (
    AnalysisResult,
    AnalysisRound,
    estimated_tokens,
    stable_digest,
)
from wintermute.ai.provider import (
    COMPATIBLE_TEMPERATURE,
    OpenAICompatibleProvider,
)
from wintermute.ai.retrieval import (
    EvidenceCatalog,
)
from wintermute.ai.scan_profile import (
    ScanProfileTask,
)
from wintermute.ai.storage import (
    AIResponseCache,
    AIUsageLedger,
)


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def analysis_id(
    task: str,
) -> str:
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    return (
        f"{timestamp}-"
        f"{task.replace('.', '-')}-"
        f"{uuid.uuid4().hex[:12]}"
    )


class AIGateway:
    def __init__(
        self,
        settings: AISettings,
        provider: OpenAICompatibleProvider,
        cache: AIResponseCache,
        ledger: AIUsageLedger,
    ) -> None:
        self.settings = settings
        self.provider = provider
        self.cache = cache
        self.ledger = ledger

    def scan_profile(
        self,
        catalog: EvidenceCatalog,
        *,
        repository_alias: str,
        tenant_alias: str,
    ) -> AnalysisResult:
        task = ScanProfileTask()
        selected_ids = list(
            task.initial_evidence_ids(
                catalog,
                limit=(
                    self.settings
                    .initial_evidence_files
                ),
            )
        )
        rounds: list[AnalysisRound] = []
        final_result: (
            dict[str, Any] | None
        ) = None
        final_evidence_ids: tuple[
            str,
            ...
        ] = ()
        input_digest = stable_digest(
            {
                "task": task.name,
                "version": task.version,
                "catalog": (
                    catalog
                    .descriptor_payload()
                ),
            }
        )

        for round_number in range(
            1,
            self.settings.max_rounds + 1,
        ):
            selected_ids = list(
                dict.fromkeys(selected_ids)
            )

            if (
                len(selected_ids)
                > self.settings
                .max_evidence_files
            ):
                raise RuntimeError(
                    "AI evidence file budget "
                    "was exceeded"
                )

            evidence, _ = (
                catalog.evidence_payload(
                    tuple(selected_ids),
                    max_bytes=(
                        self.settings
                        .max_evidence_bytes
                    ),
                )
            )

            if (
                len(evidence)
                != len(selected_ids)
            ):
                raise RuntimeError(
                    "AI evidence byte budget "
                    "was exceeded"
                )

            payload = task.request_payload(
                repository_alias=(
                    repository_alias
                ),
                catalog=(
                    catalog
                    .descriptor_payload()
                ),
                evidence=evidence,
                round_number=round_number,
            )
            user_content = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )

            if (
                len(
                    user_content.encode(
                        "utf-8"
                    )
                )
                > self.settings
                .max_prompt_bytes
            ):
                raise RuntimeError(
                    "AI prompt byte budget "
                    "was exceeded"
                )

            messages = [
                {
                    "role": "system",
                    "content": (
                        task.system_prompt()
                    ),
                },
                {
                    "role": "user",
                    "content": user_content,
                },
            ]
            request_digest = stable_digest(
                {
                    "provider": (
                        self.settings.provider
                    ),
                    "model": (
                        self.settings.model
                    ),
                    "task": task.name,
                    "task_version": (
                        task.version
                    ),
                    "generation": {
                        "temperature": (
                            COMPATIBLE_TEMPERATURE
                        ),
                        "max_output_tokens": (
                            self.settings
                            .max_output_tokens
                        ),
                        "response_format": (
                            "json_object"
                        ),
                    },
                    "messages": messages,
                }
            )
            cached = self.cache.get(
                request_digest
            )
            started = time.monotonic()

            if cached is not None:
                response = cached
                cache_hit = True
            else:
                response = (
                    self.provider.complete(
                        messages
                    )
                )
                cache_hit = False
                self.cache.put(
                    request_digest,
                    provider=(
                        self.settings.provider
                    ),
                    model=self.settings.model,
                    task=task.name,
                    response=response,
                )

            latency = (
                time.monotonic() - started
            )
            cost = self.ledger.record(
                tenant=tenant_alias,
                task=task.name,
                settings=self.settings,
                request_digest=(
                    request_digest
                ),
                cache_hit=cache_hit,
                estimated_input_tokens=(
                    estimated_tokens(
                        task.system_prompt()
                        + user_content
                    )
                ),
                response=response,
                latency_seconds=latency,
            )
            decision = task.parse(
                response.content,
                catalog,
            )
            requested = (
                decision.evidence_ids
                if decision.status
                == "request_evidence"
                else ()
            )
            rounds.append(
                AnalysisRound(
                    round_number=round_number,
                    request_digest=(
                        request_digest
                    ),
                    cache_hit=cache_hit,
                    requested_evidence_ids=(
                        requested
                    ),
                    usage=response.usage,
                    estimated_cost_usd=cost,
                    latency_seconds=latency,
                )
            )

            if decision.status == "complete":
                final_result = (
                    decision.result
                )
                final_evidence_ids = (
                    decision.evidence_ids
                )
                break

            additions = [
                evidence_id
                for evidence_id
                in decision.evidence_ids
                if evidence_id
                not in selected_ids
            ]

            if not additions:
                raise RuntimeError(
                    "AI requested no new evidence"
                )

            if (
                len(selected_ids)
                + len(additions)
                > self.settings
                .max_evidence_files
            ):
                raise RuntimeError(
                    "AI requested more evidence "
                    "than policy allows"
                )

            selected_ids.extend(additions)

        if final_result is None:
            raise RuntimeError(
                "AI did not complete the task "
                "within the round limit"
            )

        return AnalysisResult(
            analysis_id=analysis_id(
                task.name
            ),
            task=task.name,
            task_version=task.version,
            provider=self.settings.provider,
            model=self.settings.model,
            input_digest=input_digest,
            result=final_result,
            evidence_ids=(
                final_evidence_ids
            ),
            rounds=tuple(rounds),
            created_at=now_text(),
        )
