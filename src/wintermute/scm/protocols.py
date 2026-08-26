from __future__ import annotations

from typing import Protocol, runtime_checkable

from wintermute.scm.controls import (
    ControlInventory,
)
from wintermute.scm.models import (
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.observations import (
    ScmObservationResult,
)


@runtime_checkable
class ScmInventoryProvider(Protocol):
    provider: str
    provider_instance: str

    def list_tenants(
        self,
    ) -> tuple[ScmTenant, ...]:
        """Return configured, readable SCM tenants."""

    def inventory(
        self,
        tenant: ScmTenant,
    ) -> RepositoryInventory:
        """Return normalized repository inventory for one tenant."""


@runtime_checkable
class ScmControlProvider(Protocol):
    provider: str
    provider_instance: str

    def controls(
        self,
        tenant: ScmTenant,
        inventory: RepositoryInventory,
    ) -> ControlInventory:
        """Return normalized onboarding controls."""


@runtime_checkable
class ScmObservationProvider(Protocol):
    provider: str
    provider_instance: str

    def observe(
        self,
        tenant: ScmTenant,
        inventory: RepositoryInventory,
    ) -> ScmObservationResult:
        """Gather broad read-only SCM evidence and controls."""
