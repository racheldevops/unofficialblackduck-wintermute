# Parent project discovery

The blackduck-find-parents command discovers Black Duck project versions whose BOM references another Black Duck project version.

The shared implementation lives in wintermute.blackduck. The command remains as a compatibility interface and audit tool.

## Run

    blackduck-find-parents \
      --resolve-bom-names \
      --workers 8 \
      --page-limit 500

Outputs are written under:

    .wintermute/jira/parent_projects.csv
    .wintermute/jira/parent_project_changes.csv
    .wintermute/jira/cache/parent_projects_cache.json

## Relationship identity

A relationship is identified by:

    parent_version_href
    child_version_href

Names are retained for display but do not define identity.

## Detection methods

| Method | Meaning |
|---|---|
| api-href | BOM metadata directly referenced a Black Duck project version |
| bom-component-name-version | Exact project and version name fallback |

API references are preferred. Enable the exact-name fallback with resolve-bom-names when the Black Duck response does not expose project-version links.

## Incremental cache

A project version is rescanned when it is new, changed, failed previously, too old, explicitly refreshed, or lacks a trusted update marker.

Useful options:

| Option | Purpose |
|---|---|
| refresh-all | Rescan every selected version |
| refresh-older-than-days | Maximum cache age |
| no-cache | Disable incremental reuse |
| no-refresh-failed | Do not retry previous failures |
| trust-cache-without-update-marker | Reuse versions without an update timestamp |

Failed scans retain their previous relationships to avoid reporting false removals during transient outages.

## Scale

Parent inventory and BOM scans support up to eight workers.

    blackduck-find-parents \
      --workers 8 \
      --timeout 90 \
      --retries 2 \
      --page-limit 500

Higher concurrency increases Black Duck load. Monitor retries, timeouts and HTTP 429 responses.

## TLS

Use a CA bundle in production:

    blackduck-find-parents \
      --ca-bundle /path/to/customer-ca.pem

Use insecure mode only for controlled testing.

## Cohort use

The cohort source defaults to parent-rollup and can perform discovery automatically:

    blackduck-wintermute-cohort-source \
      --scope parent-rollup \
      --resolve-bom-names

Each unique child version is collected once, while all parent contexts are retained.
