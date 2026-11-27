from __future__ import annotations

from typing import Any


class ExecutionPolicyError(RuntimeError):
    pass


def require_supported_execution(contract: dict[str, Any]) -> None:
    products = contract.get("products")
    if products != ["blackduck-sca"]:
        raise ExecutionPolicyError(
            "Real execution currently supports only the Black Duck SCA integration; "
            "Coverity and Polaris execution are not implemented"
        )

    raise ExecutionPolicyError(
        "Real scan execution is temporarily blocked: the pinned Bridge SCA "
        "adapter has not yet been verified to enforce scan_mode, buildless, "
        "binary_scan, detector_search_depth, and project naming. "
        "Launcher dry-run remains available. No scanner was started."
    )
