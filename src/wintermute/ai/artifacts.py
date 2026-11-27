from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.ai.models import (
    stable_digest,
)


ARTIFACT_NAMES = (
    "analysis.json",
    "evidence-catalog.json",
)


class AnalysisArtifactError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedAnalysis:
    directory: Path
    analysis: dict[str, Any]
    evidence_catalog: tuple[
        dict[str, Any],
        ...
    ]
    digest: str


def sha256_file(path: Path) -> str:
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


def read_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise AnalysisArtifactError(
            f"Could not read AI artifact "
            f"{path}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise AnalysisArtifactError(
            f"AI artifact is not an object: "
            f"{path}"
        )

    return payload


def load_verified_analysis(
    directory: str | Path,
) -> LoadedAnalysis:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise AnalysisArtifactError(
            f"AI analysis does not exist: {root}"
        )

    ready = read_object(root / "READY")
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise AnalysisArtifactError(
            "AI analysis checksums are invalid"
        )

    for name in ARTIFACT_NAMES:
        expected = str(
            checksums.get(name) or ""
        )

        if not expected:
            raise AnalysisArtifactError(
                f"Missing checksum for {name}"
            )

        try:
            actual = sha256_file(root / name)
        except OSError as error:
            raise AnalysisArtifactError(
                f"Could not read {name}: {error}"
            ) from error

        if actual != expected:
            raise AnalysisArtifactError(
                f"Checksum mismatch for {name}"
            )

    analysis = read_object(
        root / "analysis.json"
    )
    analysis_id = str(
        analysis.get("analysis_id") or ""
    )

    if not analysis_id:
        raise AnalysisArtifactError(
            "AI analysis has no analysis ID"
        )

    if ready.get("analysis_id") != analysis_id:
        raise AnalysisArtifactError(
            "AI READY marker does not match "
            "the analysis"
        )

    if analysis.get("task") != (
        "scm.scan-profile"
    ):
        raise AnalysisArtifactError(
            "AI analysis is not a scan profile"
        )

    result = analysis.get("result")

    if not isinstance(result, dict):
        raise AnalysisArtifactError(
            "AI analysis result is invalid"
        )

    catalog_payload = read_object(
        root / "evidence-catalog.json"
    )
    raw_catalog = catalog_payload.get(
        "evidence"
    )

    if (
        not isinstance(raw_catalog, list)
        or not all(
            isinstance(value, dict)
            for value in raw_catalog
        )
    ):
        raise AnalysisArtifactError(
            "AI evidence catalog is invalid"
        )

    catalog = tuple(
        dict(value)
        for value in raw_catalog
    )
    known_ids = {
        str(value.get("evidence_id") or "")
        for value in catalog
    }
    cited_ids = result.get(
        "evidence_ids"
    )

    if (
        not isinstance(cited_ids, list)
        or not all(
            isinstance(value, str)
            for value in cited_ids
        )
    ):
        raise AnalysisArtifactError(
            "AI scan profile citations are invalid"
        )

    unknown = set(cited_ids) - known_ids

    if unknown:
        raise AnalysisArtifactError(
            "AI scan profile cites unknown "
            "evidence IDs: "
            + ", ".join(sorted(unknown))
        )

    return LoadedAnalysis(
        directory=root,
        analysis=analysis,
        evidence_catalog=catalog,
        digest=stable_digest(
            {
                "analysis": analysis,
                "evidence_catalog": catalog,
            }
        ),
    )
