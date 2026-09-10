from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from wintermute.ai.models import stable_digest


DEPTH_BUCKETS = (
    0,
    3,
    5,
    10,
    20,
)


@dataclass(frozen=True)
class ApprovedTemplate:
    template_id: str
    engine: str
    products: tuple[str, ...]
    central_template: str
    supported_modes: tuple[str, ...]
    resource_class: str = "medium"
    timeout_seconds: int = 3600
    template_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "template_version": (
                self.template_version
            ),
            "engine": self.engine,
            "products": list(self.products),
            "central_template": (
                self.central_template
            ),
            "supported_modes": list(
                self.supported_modes
            ),
            "resource_class": (
                self.resource_class
            ),
            "timeout_seconds": (
                self.timeout_seconds
            ),
        }


def bridge_template(
    template_id: str,
    central_template: str,
    supported_modes: tuple[str, ...],
    *,
    resource_class: str = "medium",
    timeout_seconds: int = 3600,
) -> ApprovedTemplate:
    return ApprovedTemplate(
        template_id=template_id,
        engine="bridge",
        products=("blackduck-sca",),
        central_template=central_template,
        supported_modes=supported_modes,
        resource_class=resource_class,
        timeout_seconds=timeout_seconds,
    )


APPROVED_TEMPLATES = {
    "cargo": bridge_template(
        "cargo-security-scan",
        "cargo",
        ("detector", "hybrid"),
    ),
    "dotnet": bridge_template(
        "dotnet-security-scan",
        "dotnet",
        ("detector", "hybrid"),
    ),
    "generic-detect": bridge_template(
        "generic-security-scan",
        "generic-detect",
        (
            "detector",
            "hybrid",
            "signature",
        ),
    ),
    "go": bridge_template(
        "go-security-scan",
        "go",
        ("detector", "hybrid"),
    ),
    "gradle": bridge_template(
        "gradle-security-scan",
        "gradle",
        ("detector", "hybrid"),
        resource_class="large",
    ),
    "maven": bridge_template(
        "maven-security-scan",
        "maven",
        ("detector", "hybrid"),
        resource_class="large",
    ),
    "mixed": bridge_template(
        "mixed-security-scan",
        "mixed",
        ("detector", "hybrid"),
        resource_class="large",
        timeout_seconds=5400,
    ),
    "npm": bridge_template(
        "npm-security-scan",
        "npm",
        ("detector", "hybrid"),
    ),
    "python": bridge_template(
        "python-security-scan",
        "python",
        ("detector", "hybrid"),
    ),
}


def approved_catalog() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "templates": [
            APPROVED_TEMPLATES[key].as_dict()
            for key in sorted(
                APPROVED_TEMPLATES
            )
        ],
    }


def normalized_depth(
    profile: dict[str, Any],
) -> int:
    layout = str(
        profile.get("layout")
        or "unknown"
    )
    layout_minimum = {
        "single-project": 3,
        "monorepo": 10,
        "unknown": 5,
    }.get(layout, 5)
    parameters = profile.get(
        "parameters"
    )
    requested = layout_minimum

    if isinstance(parameters, dict):
        raw_depth = parameters.get(
            "detector_search_depth"
        )

        if type(raw_depth) is int:
            requested = max(
                layout_minimum,
                raw_depth,
            )

    for bucket in DEPTH_BUCKETS:
        if requested <= bucket:
            return bucket

    return DEPTH_BUCKETS[-1]


def template_contract(
    profile: dict[str, Any],
) -> tuple[
    dict[str, Any] | None,
    tuple[str, ...],
]:
    reasons: list[str] = []
    selected = str(
        profile.get(
            "central_template"
        )
        or ""
    )
    template = APPROVED_TEMPLATES.get(
        selected
    )

    if template is None:
        return (
            None,
            (
                "approved-template-unavailable",
            ),
        )

    scan_mode = str(
        profile.get("scan_mode")
        or "unknown"
    )

    if (
        scan_mode
        not in template.supported_modes
    ):
        reasons.append(
            "scan-mode-not-supported-by-template"
        )

    parameters = profile.get(
        "parameters"
    )
    parameters = (
        parameters
        if isinstance(parameters, dict)
        else {}
    )
    buildless = parameters.get(
        "buildless",
        False,
    )
    binary_scan = parameters.get(
        "binary_scan",
        False,
    )

    if type(buildless) is not bool:
        buildless = False
        reasons.append(
            "invalid-buildless-parameter"
        )

    if type(binary_scan) is not bool:
        binary_scan = False
        reasons.append(
            "invalid-binary-scan-parameter"
        )

    contract = {
        "schema_version": 1,
        "template_id": (
            template.template_id
        ),
        "template_version": (
            template.template_version
        ),
        "engine": template.engine,
        "products": list(
            template.products
        ),
        "scan_mode": scan_mode,
        "resource_class": (
            template.resource_class
        ),
        "timeout_seconds": (
            template.timeout_seconds
        ),
        "runtime_parameters": {
            "binary_scan": binary_scan,
            "buildless": buildless,
            "detector_search_depth": (
                normalized_depth(profile)
            ),
            "project_name_strategy": (
                "provider-id"
            ),
        },
    }
    contract["contract_digest"] = (
        stable_digest(contract)
    )

    return (
        contract,
        tuple(sorted(set(reasons))),
    )
