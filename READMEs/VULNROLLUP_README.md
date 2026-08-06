# Parent vulnerability rollup

The blackduck-vuln-rollup command reads parent and child relationships, collects vulnerabilities from unique child project versions, then expands direct findings across parent contexts.

It does not call Jira.

## Run

    blackduck-vuln-rollup \
      --parents-csv parent_projects.csv \
      --threshold 7 \
      --workers 8 \
      --page-limit 500 \
      --out findings.csv \
      --failures-out rollup-failures.csv

The score comparison is greater than or equal to the configured threshold.

## Required relationship fields

    parent_project
    parent_version
    parent_version_href
    child_project
    child_version
    child_version_href

Additional relationship metadata is preserved where available.

## Efficient collection

If several parents reference the same child version, Wintermute:

1. Collects that child version once.
2. Produces one direct finding identity.
3. Expands it into each parent context for Jira compatibility.

This avoids repeated Black Duck API retrieval while preserving customer product traceability.

## Finding identity

The compatibility rollup key is:

    parent project
    parent version
    child project
    child version
    component
    component version
    vulnerability

The shared direct finding identity excludes parent context.

## Failures

Failures are isolated per target or relationship and written to the failure report. Strict pipeline mode blocks Jira publishing when failures exist.

## Cache and concurrency

The command supports persistent API caching and up to eight project-version workers.

Useful options:

| Option | Purpose |
|---|---|
| workers | Concurrent child-version collection |
| page-limit | Black Duck API page size |
| refresh-api-cache | Ignore the existing API cache |
| api-cache-max-age-hours | Maximum cache age |
| api-cache-max-entries | Cache size limit |
| only-child-href | Retry one exact child version |

## Recommended production path

For a multi-destination deployment, prefer the cohort source:

    blackduck-wintermute-cohort-source \
      --scope parent-rollup \
      --strict \
      --resolve-bom-names

Jira and Datadog can then consume the same immutable source snapshot.
