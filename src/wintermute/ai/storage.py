from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wintermute.ai.config import AISettings
from wintermute.ai.models import (
    AnalysisResult,
    ModelResponse,
    ModelUsage,
)


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class AIResponseCache:
    def __init__(
        self,
        path: Path,
    ) -> None:
        self.path = path
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self._lock = threading.RLock()
        self._database = sqlite3.connect(
            self.path,
            check_same_thread=False,
        )
        self._database.execute(
            """
            CREATE TABLE IF NOT EXISTS responses (
                cache_key TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                task TEXT NOT NULL,
                created_at TEXT NOT NULL,
                content TEXT NOT NULL,
                usage_json TEXT NOT NULL
            )
            """
        )
        self._database.commit()

    def get(
        self,
        cache_key: str,
    ) -> ModelResponse | None:
        with self._lock:
            row = self._database.execute(
                """
                SELECT content, usage_json
                FROM responses
                WHERE cache_key = ?
                """,
                (cache_key,),
            ).fetchone()

        if row is None:
            return None

        usage = json.loads(row[1])

        if not isinstance(usage, dict):
            return None

        return ModelResponse(
            content=str(row[0]),
            usage=ModelUsage.from_dict(
                usage
            ),
            request_id="cache",
        )

    def put(
        self,
        cache_key: str,
        *,
        provider: str,
        model: str,
        task: str,
        response: ModelResponse,
    ) -> None:
        with self._lock:
            self._database.execute(
                """
                INSERT OR REPLACE INTO responses (
                    cache_key,
                    provider,
                    model,
                    task,
                    created_at,
                    content,
                    usage_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cache_key,
                    provider,
                    model,
                    task,
                    now_text(),
                    response.content,
                    json.dumps(
                        response.usage.as_dict(),
                        sort_keys=True,
                    ),
                ),
            )
            self._database.commit()


class AIUsageLedger:
    def __init__(
        self,
        path: Path,
    ) -> None:
        self.path = path
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self._lock = threading.RLock()
        self._database = sqlite3.connect(
            self.path,
            check_same_thread=False,
        )
        self._database.execute(
            """
            CREATE TABLE IF NOT EXISTS usage (
                usage_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                tenant TEXT NOT NULL,
                task TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                cache_hit INTEGER NOT NULL,
                estimated_input_tokens INTEGER NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cached_input_tokens INTEGER NOT NULL,
                reasoning_tokens INTEGER NOT NULL,
                estimated_cost_usd REAL NOT NULL,
                latency_seconds REAL NOT NULL,
                provider_request_id TEXT NOT NULL
            )
            """
        )
        self._database.commit()

    def record(
        self,
        *,
        tenant: str,
        task: str,
        settings: AISettings,
        request_digest: str,
        cache_hit: bool,
        estimated_input_tokens: int,
        response: ModelResponse,
        latency_seconds: float,
    ) -> float:
        cost = estimate_cost(
            settings,
            response.usage,
        )
        usage_id = uuid.uuid4().hex

        with self._lock:
            self._database.execute(
                """
                INSERT INTO usage (
                    usage_id,
                    created_at,
                    tenant,
                    task,
                    provider,
                    model,
                    request_digest,
                    cache_hit,
                    estimated_input_tokens,
                    input_tokens,
                    output_tokens,
                    cached_input_tokens,
                    reasoning_tokens,
                    estimated_cost_usd,
                    latency_seconds,
                    provider_request_id
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    usage_id,
                    now_text(),
                    tenant,
                    task,
                    settings.provider,
                    settings.model,
                    request_digest,
                    1 if cache_hit else 0,
                    estimated_input_tokens,
                    response.usage.input_tokens,
                    response.usage.output_tokens,
                    response.usage.cached_input_tokens,
                    response.usage.reasoning_tokens,
                    cost,
                    latency_seconds,
                    response.request_id,
                ),
            )
            self._database.commit()

        return cost

    def summary(self) -> dict[str, Any]:
        with self._lock:
            row = self._database.execute(
                """
                SELECT
                    COUNT(*),
                    COALESCE(SUM(cache_hit), 0),
                    COALESCE(SUM(input_tokens), 0),
                    COALESCE(SUM(output_tokens), 0),
                    COALESCE(SUM(cached_input_tokens), 0),
                    COALESCE(SUM(reasoning_tokens), 0),
                    COALESCE(SUM(estimated_cost_usd), 0)
                FROM usage
                """
            ).fetchone()

        return {
            "request_count": int(row[0]),
            "cache_hit_count": int(row[1]),
            "input_tokens": int(row[2]),
            "output_tokens": int(row[3]),
            "cached_input_tokens": int(
                row[4]
            ),
            "reasoning_tokens": int(row[5]),
            "estimated_cost_usd": round(
                float(row[6]),
                8,
            ),
        }


def estimate_cost(
    settings: AISettings,
    usage: ModelUsage,
) -> float:
    uncached_input = max(
        0,
        usage.input_tokens
        - usage.cached_input_tokens,
    )

    return (
        uncached_input
        * settings.input_cost_per_million
        / 1_000_000
        + usage.cached_input_tokens
        * settings
        .cached_input_cost_per_million
        / 1_000_000
        + usage.output_tokens
        * settings.output_cost_per_million
        / 1_000_000
        + usage.reasoning_tokens
        * settings.reasoning_cost_per_million
        / 1_000_000
    )


def atomic_write_json(
    path: Path,
    payload: Any,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    temporary = path.with_name(
        f"{path.name}.{uuid.uuid4().hex}.tmp"
    )

    try:
        with temporary.open(
            "w",
            encoding="utf-8",
        ) as output_file:
            json.dump(
                payload,
                output_file,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            output_file.write("\n")
            output_file.flush()
            os.fsync(output_file.fileno())

        os.replace(
            temporary,
            path,
        )
    finally:
        temporary.unlink(
            missing_ok=True
        )


def sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as input_file:
        for chunk in iter(
            lambda: input_file.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def write_analysis(
    root: Path,
    analysis: AnalysisResult,
    *,
    evidence_catalog: list[
        dict[str, Any]
    ],
) -> Path:
    staging = (
        root
        / ".staging"
        / analysis.analysis_id
    )
    destination = (
        root / analysis.analysis_id
    )

    if destination.exists():
        raise RuntimeError(
            f"Analysis already exists: "
            f"{destination}"
        )

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )
    artifact_names = (
        "analysis.json",
        "evidence-catalog.json",
    )

    try:
        atomic_write_json(
            staging / "analysis.json",
            analysis.as_dict(),
        )
        atomic_write_json(
            staging / "evidence-catalog.json",
            {
                "schema_version": 1,
                "evidence": evidence_catalog,
            },
        )
        checksums = {
            name: sha256_file(
                staging / name
            )
            for name in artifact_names
        }
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": checksums,
            },
        )
        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        os.replace(
            staging,
            destination,
        )
        atomic_write_json(
            destination / "READY",
            {
                "schema_version": 1,
                "analysis_id": (
                    analysis.analysis_id
                ),
                "ready_at": now_text(),
            },
        )

        return destination
    except BaseException:
        import shutil

        shutil.rmtree(
            staging,
            ignore_errors=True,
        )
        raise
