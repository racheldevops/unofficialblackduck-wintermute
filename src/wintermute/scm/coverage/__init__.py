"""SCM-to-Black-Duck coverage services."""

from wintermute.scm.coverage.blackduck import (
    observe_blackduck_inventory,
)
from wintermute.scm.coverage.blackduck_scan import (
    collect_blackduck_scan_evidence,
    collect_version_evidence,
)
from wintermute.scm.coverage.mapping import (
    map_repositories_to_blackduck,
    mapping_result_payload,
)
from wintermute.scm.coverage.metrics import (
    CoverageMetric,
    CoverageMetrics,
    classification_counts,
    coverage_breakdowns,
    coverage_metrics,
)
from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckObservationFailure,
    BlackDuckProjectObservation,
    BlackDuckVersionObservation,
    CoverageClassification,
    CoverageReport,
    ExplicitMapping,
    MappingConfidence,
    MappingMetadataFields,
    MappingMethod,
    MappingProjectRef,
    MappingResult,
    RepositoryCoverage,
    RepositoryProjectMapping,
)
from wintermute.scm.coverage.pipeline import (
    CoverageExecution,
    execute_coverage,
    load_explicit_mappings,
)
from wintermute.scm.coverage.reconciliation import (
    reconcile_coverage,
)
from wintermute.scm.coverage.reporting import (
    COVERAGE_REPORT_SCHEMA_VERSION,
    coverage_report_payload,
    repository_coverage_payload,
)
from wintermute.scm.coverage.scan_evidence import (
    apply_scan_evidence,
    load_scan_evidence,
)
from wintermute.scm.coverage.snapshot import (
    COVERAGE_SNAPSHOT_SCHEMA_VERSION,
    CoverageSnapshotError,
    LoadedCoverageSnapshot,
    load_coverage_snapshot,
    mark_coverage_complete,
    prune_coverage_snapshots,
    write_coverage_snapshot,
)


__all__ = [
    "COVERAGE_REPORT_SCHEMA_VERSION",
    "COVERAGE_SNAPSHOT_SCHEMA_VERSION",
    "BlackDuckInventoryObservation",
    "BlackDuckObservationFailure",
    "BlackDuckProjectObservation",
    "BlackDuckVersionObservation",
    "CoverageClassification",
    "CoverageExecution",
    "CoverageMetric",
    "CoverageMetrics",
    "CoverageReport",
    "CoverageSnapshotError",
    "ExplicitMapping",
    "LoadedCoverageSnapshot",
    "MappingConfidence",
    "MappingMetadataFields",
    "MappingMethod",
    "MappingProjectRef",
    "MappingResult",
    "RepositoryCoverage",
    "RepositoryProjectMapping",
    "apply_scan_evidence",
    "classification_counts",
    "collect_blackduck_scan_evidence",
    "collect_version_evidence",
    "coverage_breakdowns",
    "coverage_metrics",
    "coverage_report_payload",
    "execute_coverage",
    "load_coverage_snapshot",
    "load_explicit_mappings",
    "load_scan_evidence",
    "map_repositories_to_blackduck",
    "mapping_result_payload",
    "mark_coverage_complete",
    "observe_blackduck_inventory",
    "prune_coverage_snapshots",
    "reconcile_coverage",
    "repository_coverage_payload",
    "write_coverage_snapshot",
]
