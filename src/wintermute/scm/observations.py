from __future__ import annotations

from dataclasses import dataclass

from wintermute.scm.controls import (
    ControlInventory,
)
from wintermute.scm.evidence import (
    EvidenceInventory,
)


@dataclass(frozen=True)
class ScmObservationResult:
    evidence: EvidenceInventory
    controls: ControlInventory

    @property
    def failure_count(self) -> int:
        failures = {
            (
                failure.provider,
                failure.provider_instance,
                failure.tenant_id,
                getattr(
                    failure,
                    "repository_external_id",
                    "",
                ),
                getattr(
                    failure,
                    "name_with_owner",
                    "",
                ),
                failure.stage,
                failure.error,
            )
            for failure
            in self.evidence.failures
        }
        failures.update(
            (
                failure.provider,
                failure.provider_instance,
                failure.tenant_id,
                getattr(
                    failure,
                    "repository_external_id",
                    "",
                ),
                getattr(
                    failure,
                    "name_with_owner",
                    "",
                ),
                failure.stage,
                failure.error,
            )
            for failure
            in self.controls.failures
        )

        return len(failures)
