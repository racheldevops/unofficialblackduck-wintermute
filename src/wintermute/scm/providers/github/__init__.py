"""GitHub SCM provider services."""

from wintermute.scm.providers.github.client import (
    DEFAULT_GRAPHQL_ENDPOINT,
    GitHubClient,
    GitHubClientError,
    GitHubClientStats,
)
from wintermute.scm.providers.github.controls import (
    GitHubControlProvider,
    GitHubControlSettings,
)
from wintermute.scm.providers.github.observations import (
    GitHubObservationProvider,
    evidence_from_resources,
)
from wintermute.scm.providers.github.mapper import (
    GitHubMappingError,
    map_discovery_payload,
    map_repository,
)
from wintermute.scm.providers.github.workflows import (
    RepositoryWorkflowResult,
    collect_repository_evidence,
)
from wintermute.scm.providers.github.rest import (
    DEFAULT_REST_BASE_URL,
    GitHubRestClient,
    GitHubRestError,
    GitHubRestStats,
)


__all__ = [
    "DEFAULT_GRAPHQL_ENDPOINT",
    "DEFAULT_REST_BASE_URL",
    "GitHubClient",
    "GitHubClientError",
    "GitHubClientStats",
    "GitHubControlProvider",
    "GitHubControlSettings",
    "GitHubMappingError",
    "GitHubObservationProvider",
    "GitHubRestClient",
    "GitHubRestError",
    "GitHubRestStats",
    "evidence_from_resources",
    "RepositoryWorkflowResult",
    "collect_repository_evidence",
    "map_discovery_payload",
    "map_repository",
]
