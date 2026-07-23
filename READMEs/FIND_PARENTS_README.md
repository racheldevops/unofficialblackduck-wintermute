# Find parent Black Duck projects

Find Black Duck project versions whose BOM appears to contain other Black Duck project versions.

This is the discovery stage for Jira parent and child project relationships. It writes a relationship inventory that the vulnerability rollup can use to inspect directly affected child projects.

This module does not collect vulnerabilities and does not call Jira.

## Current module

Python module:

    harness.jira.find_parent_projects

Installed command:

    blackduck-find-parents

Equivalent module command:

    python -m harness.jira.find_parent_projects

The installed command and Python module command execute the same source code.

Source location:

    src/harness/jira/find_parent_projects.py

## Package layout

The parent discovery workflow belongs to the Jira side of the harness:

    src/harness/
    ├── jira/
    │   ├── find_parent_projects.py
    │   ├── subp_vuln_rollup.py
    │   ├── findings_hierarchy_plan.py
    │   ├── findings_to_jira.py
    │   └── config/
    │       └── jira-rollup-config.json
    ├── datadog/
    └── paths.py

Default Jira workflow outputs are stored under:

    .harness/jira/

Caches are stored under:

    .harness/jira/cache/

The output root can be changed with the HARNESS_OUTPUT_DIR environment variable.

Example:

    export HARNESS_OUTPUT_DIR="/opt/blackduck/harness-output"

With that setting, the default parent relationship file becomes:

    /opt/blackduck/harness-output/jira/parent_projects.csv

## Workflow position

The current Jira workflow is:

    Black Duck projects and versions
        |
        v
    harness.jira.find_parent_projects
        |
        v
    .harness/jira/parent_projects.csv
        |
        v
    harness.jira.subp_vuln_rollup
        |
        v
    .harness/jira/findings.csv
        |
        v
    harness.jira.findings_hierarchy_plan
        |
        v
    .harness/jira/jira-hierarchy-plan.json
        |
        v
    harness.jira.findings_to_jira
        |
        v
    Jira Epics and Tasks

## What is a parent relationship?

A parent relationship is recorded when the BOM of one Black Duck project version appears to reference another Black Duck project version.

Example:

    Product-Parent version 4.0
        |
        └── VUMA-TestProject version 1.0.0

The output relationship contains both sides:

    parent_project = Product-Parent
    parent_version = 4.0
    child_project = VUMA-TestProject
    child_version = 1.0.0

In the later vulnerability hierarchy:

- The parent project remains traceability context.
- The child project becomes the directly affected project.
- The child project is also called the subproject in findings.
- The default Jira Task title uses the affected child project and version.

Example Jira Task title:

    Black Duck: BLOCKER Alert - VUMA-TestProject - version 1.0.0 - Apache Log4j version 1.1.3

The title uses VUMA-TestProject because it is the affected child project, not the parent product container.

## Authentication

Black Duck authentication can be supplied through environment variables or command-line flags.

Recommended environment variables:

    export BLACKDUCK_URL="https://blackduck.example.com"
    export BLACKDUCK_API_TOKEN="your-token"

Equivalent flags:

    --bd-url "https://blackduck.example.com"
    --api-token "your-token"

Environment variables are preferable for IntelliJ configurations, scheduled jobs, and local terminal use because they keep credentials out of command history.

Do not store real Black Duck tokens in shared IntelliJ run configurations.

## Editable installation

Activate the existing project virtual environment and install the package as editable:

    source .venv/bin/activate
    python -m pip install -e .

An editable installation makes the installed command point at the current source tree.

You normally only need to reinstall after changing:

- pyproject.toml
- Package structure
- Installed command entry points
- Package metadata

Normal edits to find_parent_projects.py are available immediately.

## IntelliJ run configuration

Create a Python run configuration with:

| Setting | Value |
|---|---|
| Run target | Module name |
| Module name | harness.jira.find_parent_projects |
| Python interpreter | Project .venv interpreter |
| Working directory | $PROJECT_DIR$ |
| Add content roots to PYTHONPATH | Enabled |
| Add source roots to PYTHONPATH | Enabled |

Add these environment variables:

    BLACKDUCK_URL=https://blackduck.example.com
    BLACKDUCK_API_TOKEN=your-token

Example test parameters:

    --project-name-contains "goat" --max-projects 10 --debug

## Default run

The default installed command is:

    blackduck-find-parents

Equivalent module command:

    python -m harness.jira.find_parent_projects

The default run writes:

    .harness/jira/parent_projects.csv
    .harness/jira/parent_project_changes.csv
    .harness/jira/cache/parent_projects_cache.json

Default scan behavior includes:

    refresh cached entries after 7 days
    retry temporary failures twice
    use a 60 second HTTP timeout
    use one worker
    verify TLS certificates

## Explicit default run

    blackduck-find-parents \
      --out .harness/jira/parent_projects.csv \
      --changes-out .harness/jira/parent_project_changes.csv \
      --cache .harness/jira/cache/parent_projects_cache.json \
      --refresh-older-than-days 7 \
      --timeout 60 \
      --retries 2 \
      --workers 1

Equivalent module command:

    python -m harness.jira.find_parent_projects \
      --out .harness/jira/parent_projects.csv \
      --changes-out .harness/jira/parent_project_changes.csv \
      --cache .harness/jira/cache/parent_projects_cache.json \
      --refresh-older-than-days 7 \
      --timeout 60 \
      --retries 2 \
      --workers 1

## Discovery process

The module performs these operations:

1. Authenticates with Black Duck.
2. Reads the available Black Duck projects.
3. Reads the versions for each selected project.
4. Builds an inventory of project versions.
5. Selects versions that need a fresh BOM scan.
6. Reads the BOM components for each selected parent version.
7. Searches BOM data for referenced Black Duck project-version API URLs.
8. Optionally resolves BOM component names as project/version references.
9. Deduplicates relationships by parent version URL and child version URL.
10. Writes the relationship inventory.
11. Writes the relationship change report.
12. Updates the incremental cache.

## Primary detection method

The default detection method searches BOM resources for Black Duck project-version API URLs.

A detected project-version URL resembles:

    /api/projects/PROJECT-UUID/versions/VERSION-UUID

When a referenced version URL points to another Black Duck project version, the relationship is recorded as:

    detection_method = api-href

This is the preferred method because the relationship is based on a Black Duck resource identity rather than only a name match.

## BOM-name fallback

Some Black Duck versions or BOM resource shapes may not expose a project-version URL.

Enable the fallback with:

    --resolve-bom-names

Example:

    blackduck-find-parents \
      --resolve-bom-names \
      --debug

The fallback treats a BOM component as a possible Black Duck project version when:

    BOM componentName equals Black Duck project name
    BOM componentVersionName equals Black Duck version name

Relationships found this way use:

    detection_method = bom-component-name-version

The matching is exact.

The fallback can discover relationships omitted by API-link detection, but it should be reviewed more carefully because unrelated components can share names and versions with Black Duck projects.

If multiple project versions have the same name pair, debug output reports the ambiguous match.

## Testing and targeting

Use a project-name filter and safety limit for small runs.

Available flags:

| Flag | Description |
|---|---|
| --project-name-contains | Scan only projects whose names contain this text |
| --max-projects | Stop after this many selected projects |
| --debug | Print inventory, scan, cache, and matching details |

Example:

    blackduck-find-parents \
      --project-name-contains "goat" \
      --max-projects 10 \
      --debug

This still uses the normal output and cache paths under .harness/jira.

To isolate a test run from the normal files:

    blackduck-find-parents \
      --project-name-contains "goat" \
      --max-projects 10 \
      --out .harness/jira/tests/parent_projects-test.csv \
      --changes-out .harness/jira/tests/parent_project_changes-test.csv \
      --cache .harness/jira/tests/parent_projects_cache-test.json \
      --debug

Parent directories for configured outputs are created automatically.

## Output controls

| Flag | Default | Description |
|---|---|---|
| --out | .harness/jira/parent_projects.csv | Main relationship output |
| --changes-out | .harness/jira/parent_project_changes.csv | Added and removed relationship report |
| --cache | .harness/jira/cache/parent_projects_cache.json | Incremental scan cache |
| --json | Off | Write the main relationship output as JSON |
| --out - | Not default | Write the main relationship output to standard output |

The changes report remains CSV.

When JSON mode is enabled, use an output filename ending in .json for clarity.

Example:

    blackduck-find-parents \
      --json \
      --out .harness/jira/parent_projects.json

## Main relationship fields

The CSV contains:

    parent_project
    parent_version
    parent_phase
    parent_updated
    child_project
    child_version
    child_phase
    detection_method
    bom_component_name
    bom_component_version
    parent_version_href
    child_version_href
    cache_entry_status
    cache_reuse_reason
    parent_scanned_at
    parent_scan_error

## Field meanings

| Field | Meaning |
|---|---|
| parent_project | Project whose version BOM was inspected |
| parent_version | Version whose BOM was inspected |
| parent_phase | Black Duck lifecycle phase of the parent version |
| parent_updated | Black Duck update marker used by cache decisions |
| child_project | Referenced Black Duck project |
| child_version | Referenced Black Duck project version |
| child_phase | Black Duck lifecycle phase of the child version |
| detection_method | How the relationship was discovered |
| bom_component_name | BOM component name that exposed or matched the child |
| bom_component_version | BOM component version that exposed or matched the child |
| parent_version_href | Stable Black Duck API URL for the parent version |
| child_version_href | Stable Black Duck API URL for the child version |
| cache_entry_status | Status of the cached parent-version scan |
| cache_reuse_reason | Why an entry was scanned or reused |
| parent_scanned_at | Time the parent version BOM was scanned |
| parent_scan_error | Most recent parent-version scan error |

## Relationship identity and deduplication

A relationship is identified by:

    parent_version_href
    child_version_href

Duplicate detections of the same parent and child version pair are collapsed into one output row.

Project names and version names are useful display metadata but do not form the stable relationship identity.

## Relationship change report

The changes output compares the previous cached relationship set with the current relationship set.

Change types are:

    added
    removed

Example file:

    .harness/jira/parent_project_changes.csv

A relationship is added when it exists in the current scan but was not in the previous cached result.

A relationship is removed when it existed in the previous cached result but is no longer present in the current result.

An empty changes file with only a header means no relationships were added or removed.

## Incremental cache

Caching is enabled by default.

Default cache:

    .harness/jira/cache/parent_projects_cache.json

The cache stores results per parent project version.

A parent version is rescanned when:

- It is new.
- Its project/version metadata signature changed.
- The previous scan failed.
- Its cache entry reached the configured maximum age.
- A full refresh was requested.
- Black Duck did not provide an update marker and cache trust is disabled.

A cached parent version can be reused when its signature and cache settings remain valid.

## Cache refresh controls

Default maximum cache age:

    --refresh-older-than-days 7

Disable age-based refresh:

    --refresh-older-than-days -1

Force every selected project version to be scanned:

    --refresh-all

Disable the cache and scan all selected project versions without saving cache:

    --no-cache

Do not retry parent versions that failed in the previous run:

    --no-refresh-failed

Reuse cache entries even when Black Duck does not provide a parent-version update marker:

    --trust-cache-without-update-marker

The trust option improves reuse but can miss relationship changes when Black Duck supplies no reliable update timestamp.

## Failed scans and retained relationships

If a parent-version scan fails, the cache records:

    status = failed
    error = failure message
    scanned_at = failure time

When a failed parent version already had cached relationships, the previous relationships are retained instead of being discarded immediately.

This avoids reporting every existing child relationship as removed because of one temporary Black Duck API failure.

Unless --no-refresh-failed is supplied, failed entries are retried during the next run.

## Cache reuse reasons

Cache metadata can contain reasons such as:

    new-version
    version-changed
    previous-scan-failed
    refresh-all
    no-cache
    no-update-marker
    cache-age-unknown
    cache-older-than-N-days
    unchanged-cache-hit

These values help explain why a parent version was scanned or reused.

## HTTP controls

| Flag | Default | Description |
|---|---:|---|
| --timeout | 60 | Per-request timeout in seconds |
| --retries | 2 | Retry count after temporary server or network failures |
| --retry-delay | 2.0 | Base delay between retries |
| --workers | 1 | Concurrent project-version BOM scans |

Temporary retryable HTTP statuses include:

    429
    500
    502
    503
    504

Worker counts from one through four are recommended.

A higher worker count can reduce scan time but also increases Black Duck API load.

## TLS controls

Certificate validation is enabled by default.

For an internal certificate authority:

    blackduck-find-parents \
      --ca-bundle /path/to/internal-ca.pem

For temporary lab testing only:

    blackduck-find-parents \
      --insecure

Do not use --insecure and --ca-bundle together.

Using a CA bundle is preferred for production and customer environments.

## Debug output

Enable debug output with:

    --debug

Debug information is written to standard error and can include:

- Project inventory progress
- Parent-version scan progress
- Cache reuse decisions
- Ambiguous BOM-name matches
- Failed project or version reads
- Worker completion progress

The main CSV or JSON output remains separate.

## Common production-style run

    export BLACKDUCK_URL="https://blackduck.example.com"
    export BLACKDUCK_API_TOKEN="your-token"

    blackduck-find-parents \
      --refresh-older-than-days 7 \
      --timeout 60 \
      --retries 2 \
      --retry-delay 2.0 \
      --workers 2

Outputs:

    .harness/jira/parent_projects.csv
    .harness/jira/parent_project_changes.csv
    .harness/jira/cache/parent_projects_cache.json

## Full rescan example

    blackduck-find-parents \
      --refresh-all \
      --workers 2 \
      --debug

## No-cache test example

    blackduck-find-parents \
      --project-name-contains "VUMA" \
      --max-projects 5 \
      --no-cache \
      --out .harness/jira/tests/vuma-parent-projects.csv \
      --changes-out .harness/jira/tests/vuma-parent-changes.csv \
      --debug

## BOM-name fallback example

    blackduck-find-parents \
      --resolve-bom-names \
      --refresh-older-than-days 7 \
      --workers 2 \
      --debug

## Scheduled run example

A scheduled process can set a dedicated output root:

    export HARNESS_OUTPUT_DIR="/opt/blackduck/harness-output"
    export BLACKDUCK_URL="https://blackduck.example.com"
    export BLACKDUCK_API_TOKEN="your-token"

    blackduck-find-parents \
      --refresh-older-than-days 7 \
      --timeout 60 \
      --retries 2 \
      --workers 2

The resulting files are written under:

    /opt/blackduck/harness-output/jira/

## Handoff to vulnerability rollup

The default relationship output is already the default input expected for the next Jira workflow stage.

Run parent discovery:

    blackduck-find-parents

Then run vulnerability rollup:

    blackduck-vuln-rollup \
      --parents-csv .harness/jira/parent_projects.csv

Equivalent module command:

    python -m harness.jira.subp_vuln_rollup \
      --parents-csv .harness/jira/parent_projects.csv

The vulnerability rollup:

- Loads each child project version.
- Reads vulnerable BOM components.
- Reads matching vulnerabilities.
- Retrieves CVSS data.
- Attempts to retrieve the E+H Entity project custom field.
- Writes .harness/jira/findings.csv.

Parent discovery itself does not retrieve E+H Entity. Entity belongs to the later vulnerability rollup stage because the affected child project is known there.

## Relationship to Jira hierarchy

The parent relationship file provides traceability between a product or container project and its affected child projects.

In the default vulnerability-project hierarchy:

- One Epic is created per vulnerability.
- One Task is created per vulnerability and affected child project/version.
- The parent project is retained as rollup context.
- The child project drives the Task project and version values.
- Parent and child relationship data does not directly create Jira parent links.

Jira parent links in the default hierarchy connect:

    CVE Epic
        |
        └── affected project-version Task

They do not reproduce the Black Duck parent and child project relationship as Jira hierarchy levels.

Use the legacy project-subproject-vulnerability hierarchy mode if the Jira hierarchy itself needs to be project-centered.

## Notes

- This module calls Black Duck.
- This module does not call Jira.
- This module does not collect vulnerability findings.
- This module does not retrieve E+H Entity.
- It only discovers parent and child Black Duck project-version relationships.
- API URL detection is preferred over BOM-name fallback.
- Incremental cache reuse is enabled by default.
- Generated output belongs under .harness/jira rather than the repository root.
- Installed commands and module execution use the same Python source.
- Review BOM-name fallback relationships before relying on them in production.
