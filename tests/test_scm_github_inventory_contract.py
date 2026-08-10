from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from wintermute.scm.inventory import (
    inventory_payload,
)
from wintermute.scm.providers.github.mapper import (
    GitHubMappingError,
    map_discovery_payload,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = (
    ROOT
    / "tests"
    / "fixtures"
    / "scm"
    / "github"
)
DISCOVERY_FIXTURE = (
    FIXTURE_ROOT / "discovery-page.json"
)
GOLDEN_INVENTORY = (
    FIXTURE_ROOT / "inventory-golden.json"
)
ACTIVITY_CUTOFF = datetime(
    2026,
    2,
    1,
    tzinfo=timezone.utc,
)


def load_object(
    path: Path,
) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8")
    )

    assert isinstance(value, dict)
    return value


def mapped_payload(
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    inventory = map_discovery_payload(
        payload or load_object(
            DISCOVERY_FIXTURE
        ),
        provider_instance="github.example",
        tenant_id="O_acme",
        namespace="acme",
        activity_cutoff=ACTIVITY_CUTOFF,
    )

    return inventory_payload(inventory)


def test_github_inventory_matches_frozen_contract() -> None:
    assert mapped_payload() == load_object(
        GOLDEN_INVENTORY
    )


def test_github_inventory_reconciles_all_nodes() -> None:
    payload = mapped_payload()

    assert payload[
        "discovered_repository_count"
    ] == 3
    assert payload["repository_count"] == 2
    assert payload["exclusion_count"] == 1
    assert payload["failure_count"] == 0
    assert payload["reconciled"] is True


def test_github_inventory_preserves_native_identity() -> None:
    repositories = {
        repository["repository_id"]: repository
        for repository
        in mapped_payload()["repositories"]
    }

    assert repositories[
        "R_service_api"
    ]["name_with_owner"] == (
        "acme/service-api"
    )
    assert repositories[
        "R_service_api"
    ]["provider"] == "github"
    assert repositories[
        "R_service_api"
    ]["provider_instance"] == (
        "github.example"
    )
    assert repositories[
        "R_service_api"
    ]["tenant_id"] == "O_acme"


def test_repository_mapping_failure_is_isolated() -> None:
    payload = copy.deepcopy(
        load_object(DISCOVERY_FIXTURE)
    )
    nodes = payload[
        "data"
    ]["organization"]["repositories"]["nodes"]
    nodes[1]["visibility"] = "SECRET"

    mapped = mapped_payload(payload)

    assert mapped["repository_count"] == 1
    assert mapped["exclusion_count"] == 1
    assert mapped["failure_count"] == 1
    assert mapped["reconciled"] is True
    assert mapped["failures"][0][
        "repository_id"
    ] == "R_docs"
    assert mapped["failures"][0][
        "stage"
    ] == "map-repository"


def test_incomplete_discovery_is_rejected() -> None:
    payload = copy.deepcopy(
        load_object(DISCOVERY_FIXTURE)
    )
    connection = payload[
        "data"
    ]["organization"]["repositories"]
    connection["pageInfo"][
        "hasNextPage"
    ] = True

    with pytest.raises(
        GitHubMappingError,
        match="incomplete",
    ):
        mapped_payload(payload)


def test_discovery_count_mismatch_is_rejected() -> None:
    payload = copy.deepcopy(
        load_object(DISCOVERY_FIXTURE)
    )
    payload[
        "data"
    ]["organization"]["repositories"][
        "totalCount"
    ] = 4

    with pytest.raises(
        GitHubMappingError,
        match="count",
    ):
        mapped_payload(payload)


def test_github_fixture_contains_no_credentials() -> None:
    text = DISCOVERY_FIXTURE.read_text(
        encoding="utf-8",
    ).casefold()

    for forbidden in (
        "authorization",
        "bearer ",
        "github_token",
        "github_pat_",
        "ghp_",
    ):
        assert forbidden not in text
