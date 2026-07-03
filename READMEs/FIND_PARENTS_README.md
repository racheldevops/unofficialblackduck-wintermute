# `find_parent_projects.py`

Find Black Duck project versions whose BOM appears to contain other Black Duck project versions.

This is the discovery stage for parent/child project relationships. It writes `parent_projects.csv`, which can then be used by the vulnerability rollup workflow.

## Purpose

```text
Black Duck projects/versions
    ↓
find_parent_projects.py
    ↓
parent_projects.csv
    ↓
subp_vuln_rollup.py
```

## Auth

Use either environment variables or CLI flags.

### Environment variables

```bash
export BLACKDUCK_URL="https://blackduck.example.com"
export BLACKDUCK_API_TOKEN="..."
```

### Equivalent flags

```bash
--bd-url https://blackduck.example.com
--api-token ...
```

## Common run

Installed command:

```bash
blackduck-find-parents \
  --out parent_projects.csv \
  --cache parent_projects_cache.json \
  --refresh-older-than-days 7 \
  --timeout 60 \
  --retries 2
```

Direct script run:

```bash
python find_parent_projects.py \
  --out parent_projects.csv \
  --cache parent_projects_cache.json \
  --refresh-older-than-days 7 \
  --timeout 60 \
  --retries 2
```

## BOM-name fallback

By default, the script looks for project-version API hrefs exposed in BOM data.

If no API href relationships are found, try:

```bash
--resolve-bom-names
```

This also treats BOM rows as possible Black Duck project/version references when:

```text
componentName == Black Duck project name
componentVersionName == Black Duck project version name
```

Example:

```bash
blackduck-find-parents \
  --resolve-bom-names \
  --out parent_projects.csv
```

## Test / targeting filters

Use these for smaller test runs.

```bash
--project-name-contains "my-project"
--max-projects 25
```

| Flag | Description |
|---|---|
| `--project-name-contains` | Scan only projects whose names contain this text. |
| `--max-projects` | Safety limit for testing. |

Example:

```bash
blackduck-find-parents \
  --project-name-contains "goat" \
  --max-projects 10 \
  --out parent_projects-test.csv \
  --debug
```

## Output

```bash
--out parent_projects.csv
--json
--changes-out parent_project_changes.csv
```

| Flag | Description |
|---|---|
| `--out parent_projects.csv` | Writes discovered parent/child relationships. |
| `--out -` | Writes output to stdout. |
| `--json` | Writes JSON instead of CSV. |
| `--changes-out parent_project_changes.csv` | Writes added/removed relationship diff compared to cached prior results. |

### Main CSV fields

```text
parent_project,parent_version,parent_phase,parent_updated,
child_project,child_version,child_phase,detection_method,
bom_component_name,bom_component_version,
parent_version_href,child_version_href,
cache_entry_status,cache_reuse_reason,
parent_scanned_at,parent_scan_error
```

## Detection methods

| Method | Meaning |
|---|---|
| `api-href` | Child project version was detected from a project-version API href in BOM data. |
| `bom-component-name-version` | Child project version was matched by BOM component name/version. Requires `--resolve-bom-names`. |

## Cache

Incremental cache is enabled by default.

```bash
--cache parent_projects_cache.json
--refresh-older-than-days 7
```

Disable cache and scan everything:

```bash
--no-cache
```

Force a full rescan while still writing cache:

```bash
--refresh-all
```

Do not retry entries that failed last time:

```bash
--no-refresh-failed
```

Reuse cache even when Black Duck does not expose an updated timestamp:

```bash
--trust-cache-without-update-marker
```

### Cache behavior

The cache stores scan results per parent project version.

A parent version is rescanned when:

- it is new
- its metadata changed
- the previous scan failed
- the cache entry is older than `--refresh-older-than-days`
- `--refresh-all` is used
- Black Duck has no update marker and cache trust is not enabled

## HTTP / TLS

```bash
--timeout 60
--retries 2
--retry-delay 2.0
--workers 1
--insecure
--ca-bundle /path/to/ca.pem
```

| Flag | Description |
|---|---|
| `--timeout` | Per-request timeout in seconds. Default: `60`. |
| `--retries` | Retry count for timeout/temporary server errors. Default: `2`. |
| `--retry-delay` | Base retry delay in seconds. Default: `2.0`. |
| `--workers` | Concurrent project-version BOM checks. Use `1-4`. Default: `1`. |
| `--insecure` | Disables TLS certificate validation. Useful for lab/on-prem testing only. |
| `--ca-bundle` | PEM CA bundle for internal/self-signed certificates. Use instead of `--insecure`. |

## Debug

```bash
--debug
```

Prints inventory, scan, cache, and progress details to stderr.

Useful for test runs or troubleshooting unexpected relationship output.

## Example full scan

```bash
blackduck-find-parents \
  --out parent_projects.csv \
  --changes-out parent_project_changes.csv \
  --cache parent_projects_cache.json \
  --refresh-older-than-days 7 \
  --timeout 60 \
  --retries 2 \
  --workers 2
```

## Example with BOM-name fallback

```bash
blackduck-find-parents \
  --resolve-bom-names \
  --out parent_projects.csv \
  --changes-out parent_project_changes.csv \
  --cache parent_projects_cache.json \
  --timeout 60 \
  --retries 2
```

## Cron example

```bash
blackduck-find-parents \
  --out /opt/blackduck/parent_projects.csv \
  --changes-out /opt/blackduck/parent_project_changes.csv \
  --cache /opt/blackduck/parent_projects_cache.json \
  --refresh-older-than-days 7 \
  --timeout 60 \
  --retries 2
```

## Notes

- This script does **not** collect vulnerability findings.
- This script does **not** call Jira.
- It only discovers parent/child Black Duck project-version relationships.
- Use the generated `parent_projects.csv` as input to `subp_vuln_rollup.py`.