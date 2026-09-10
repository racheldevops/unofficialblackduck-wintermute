from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from wintermute.ai.models import stable_digest


SUPPORTED_ENGINES = {"bridge"}
SUPPORTED_PRODUCTS = {"blackduck-sca", "coverity", "polaris"}
SUPPORTED_PROVIDERS = {"github", "gitlab"}
SUPPORTED_SCAN_MODES = {"detector", "hybrid", "signature"}
ALLOWED_PARAMETERS = {
    "binary_scan",
    "buildless",
    "detector_search_depth",
    "project_name_strategy",
}
MAX_REGISTRY_BYTES = 16 * 1024 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ScanRegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class ResolvedScan:
    contract_id: str
    provider: str
    provider_instance: str
    repository_id: str
    contract: dict[str, Any]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_instance(value: str) -> str:
    selected = str(value or "").strip()
    if not selected:
        return ""

    if any(character.isspace() for character in selected):
        raise ScanRegistryError("Provider instance contains whitespace")

    is_url = "://" in selected
    try:
        parsed = urlsplit(selected if is_url else f"//{selected}")
        port = parsed.port
    except ValueError as error:
        raise ScanRegistryError("Provider instance is invalid") from error

    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (is_url and parsed.scheme.casefold() != "https")
        or (not is_url and parsed.path)
    ):
        raise ScanRegistryError("Provider instance is invalid")

    if is_url and parsed.path.rstrip("/") not in {
        "",
        "/api/v3",
        "/api/v4",
        "/graphql",
        "/api/graphql",
    }:
        raise ScanRegistryError(
            "Provider instance URL must identify an origin or supported API root"
        )

    host = parsed.hostname.casefold()
    if ":" in host:
        host = f"[{host}]"

    if port is not None:
        return f"{host}:{port}"
    return host


def instance_identity(provider: str, value: str) -> str:
    instance = normalized_instance(value)
    if provider == "github" and instance.startswith("api."):
        return instance[4:]
    return instance


def instances_match(provider: str, first: str, second: str) -> bool:
    left = instance_identity(provider, first)
    right = instance_identity(provider, second)
    return bool(left and right and left == right)


def repository_identifier(value: Any, provider: str) -> str:
    if type(value) not in {str, int}:
        raise ScanRegistryError("Repository ID must be a string or integer")

    selected = str(value).strip()
    if not selected:
        raise ScanRegistryError("Repository ID is missing")

    if provider == "gitlab":
        if re.fullmatch(r"[1-9][0-9]*", selected) is None:
            raise ScanRegistryError(
                "GitLab repository ID must be a positive numeric identifier"
            )
    elif any(character.isspace() for character in selected):
        raise ScanRegistryError("Repository ID contains whitespace")

    return selected


def validate_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScanRegistryError("Scan contract must be an object")

    if "schema_version" in value and (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ScanRegistryError("Scan contract schema is invalid")

    engine = value.get("engine")
    if not isinstance(engine, str) or engine not in SUPPORTED_ENGINES:
        raise ScanRegistryError(f"Unsupported scan engine: {engine}")

    products = value.get("products")
    if (
        not isinstance(products, list)
        or not products
        or not all(
            isinstance(product, str) and product in SUPPORTED_PRODUCTS
            for product in products
        )
    ):
        raise ScanRegistryError("Scan contract products are invalid")
    if len(products) != len(set(products)):
        raise ScanRegistryError("Scan contract products contain duplicates")

    timeout = value.get("timeout_seconds")
    if type(timeout) is not int or not 60 <= timeout <= 14400:
        raise ScanRegistryError(
            "Scan timeout must be between 60 and 14400 seconds"
        )

    if "scan_mode" in value and (
        not isinstance(value["scan_mode"], str)
        or value["scan_mode"] not in SUPPORTED_SCAN_MODES
    ):
        raise ScanRegistryError("Scan contract scan mode is invalid")

    parameters = value.get("runtime_parameters")
    if (
        not isinstance(parameters, dict)
        or not set(parameters).issubset(ALLOWED_PARAMETERS)
    ):
        raise ScanRegistryError("Scan runtime parameters are invalid")

    for name in ("binary_scan", "buildless"):
        if name in parameters and type(parameters[name]) is not bool:
            raise ScanRegistryError(f"{name} must be boolean")

    if "detector_search_depth" in parameters:
        depth = parameters["detector_search_depth"]
        if type(depth) is not int or not 0 <= depth <= 20:
            raise ScanRegistryError("Detector search depth is invalid")

    if "project_name_strategy" in parameters:
        strategy = parameters["project_name_strategy"]
        if not isinstance(strategy, str) or strategy not in {
            "provider-id",
            "repository",
            "repository-path",
        }:
            raise ScanRegistryError("Project-name strategy is invalid")

    if "contract_digest" in value:
        claimed = value["contract_digest"]
        unsigned = dict(value)
        unsigned.pop("contract_digest")
        try:
            actual = stable_digest(unsigned)
        except (TypeError, ValueError) as error:
            raise ScanRegistryError("Scan contract content is invalid") from error

        if not isinstance(claimed, str) or claimed != actual:
            raise ScanRegistryError("Scan contract digest mismatch")

    return copy.deepcopy(value)


def validate_registry(payload: Any) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
    ):
        raise ScanRegistryError("Scan registry schema is invalid")

    contracts = payload.get("contracts")
    assignments = payload.get("assignments")
    if not isinstance(contracts, list) or not isinstance(assignments, list):
        raise ScanRegistryError("Scan registry collections are invalid")

    contract_ids: set[str] = set()
    for item in contracts:
        if not isinstance(item, dict):
            raise ScanRegistryError("Scan contract entry is invalid")
        contract_id = item.get("scan_contract_id")
        if (
            not isinstance(contract_id, str)
            or not contract_id.strip()
            or contract_id != contract_id.strip()
            or contract_id in contract_ids
        ):
            raise ScanRegistryError("Scan contract identity is invalid")

        validate_contract(item.get("contract"))
        contract_ids.add(contract_id)

    identities: set[tuple[str, str, str]] = set()
    for item in assignments:
        if not isinstance(item, dict):
            raise ScanRegistryError("Scan assignment is invalid")

        provider = item.get("provider")
        if not isinstance(provider, str) or provider not in SUPPORTED_PROVIDERS:
            raise ScanRegistryError("Scan assignment provider is invalid")

        raw_instance = item.get("provider_instance")
        if not isinstance(raw_instance, str):
            raise ScanRegistryError("Scan assignment provider instance is invalid")
        instance = instance_identity(provider, raw_instance)
        repository_id = repository_identifier(item.get("repository_id"), provider)
        contract_id = item.get("scan_contract_id")

        if (
            not instance
            or not isinstance(contract_id, str)
            or contract_id not in contract_ids
        ):
            raise ScanRegistryError("Scan assignment fields are invalid")

        identity = (provider, instance, repository_id)
        if identity in identities:
            raise ScanRegistryError("Duplicate scan assignment")
        identities.add(identity)

    return copy.deepcopy(payload)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ScanRegistryError("Scan registry contains a duplicate JSON key")
        result[name] = value
    return result


def reject_constant(value: str) -> None:
    raise ScanRegistryError(
        f"Scan registry contains a non-finite JSON number: {value}"
    )


def load_registry(
    path: str | Path,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    selected_path = Path(path).expanduser()
    expected = str(expected_sha256 or "").strip().removeprefix(
        "sha256:"
    ).casefold()
    if SHA256_PATTERN.fullmatch(expected) is None:
        raise ScanRegistryError("Expected registry SHA-256 is invalid")

    try:
        with selected_path.open("rb") as input_file:
            content = input_file.read(MAX_REGISTRY_BYTES + 1)
    except OSError as error:
        raise ScanRegistryError(
            f"Could not read scan registry: {selected_path}: {error}"
        ) from error

    if len(content) > MAX_REGISTRY_BYTES:
        raise ScanRegistryError("Scan registry exceeded the size limit")
    if hashlib.sha256(content).hexdigest() != expected:
        raise ScanRegistryError("Scan registry checksum mismatch")

    try:
        payload = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ScanRegistryError("Scan registry JSON is invalid") from error

    return validate_registry(payload)


def resolve_scan(
    registry: dict[str, Any],
    *,
    provider: str,
    provider_instance: str,
    repository_id: str,
) -> ResolvedScan:
    selected_provider = str(provider or "").strip().casefold()
    if selected_provider not in SUPPORTED_PROVIDERS:
        raise ScanRegistryError("Runtime SCM provider is invalid")

    selected_repository = repository_identifier(
        repository_id,
        selected_provider,
    )
    selected_instance = normalized_instance(provider_instance)
    if not selected_instance:
        raise ScanRegistryError("Runtime provider instance is missing")

    matches = [
        item
        for item in registry["assignments"]
        if (
            item["provider"] == selected_provider
            and str(item["repository_id"]) == selected_repository
            and instances_match(
                selected_provider,
                item["provider_instance"],
                selected_instance,
            )
        )
    ]
    if not matches:
        raise ScanRegistryError("Repository has no approved scan assignment")
    if len(matches) != 1:
        raise ScanRegistryError("Repository scan assignment is ambiguous")

    contract_id = matches[0]["scan_contract_id"]
    contracts = [
        item
        for item in registry["contracts"]
        if item["scan_contract_id"] == contract_id
    ]
    if not contracts:
        raise ScanRegistryError("Assigned scan contract is missing")
    if len(contracts) != 1:
        raise ScanRegistryError("Assigned scan contract is ambiguous")

    return ResolvedScan(
        contract_id=contract_id,
        provider=selected_provider,
        provider_instance=selected_instance,
        repository_id=selected_repository,
        contract=validate_contract(contracts[0]["contract"]),
    )
