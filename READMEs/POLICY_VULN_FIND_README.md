# `policy_vuln_find.py`

Find Black Duck project versions that are candidates for downstream vulnerability/policy finding collection.

This is the discovery stage for the policy/vulnerability workflow. It writes a candidate project-version CSV that can be consumed by `policy_vuln_pull.py`.

## Purpose

```text
Black Duck projects/versions
    ↓
policy_vuln_find.py
    ↓
policy_candidate_projects.csv
    ↓
policy_vuln_pull.py
```

## Auth

Use either environment variables or CLI flags.

```bash
export BLACKDUCK_URL="https://blackduck.example.com"
export BLACKDUCK_API_TOKEN="..."
```

Equivalent flags:

```bash
--bd-url https://blackduck.example.com
--api-token ...
```

## Recommended production run

```bash
blackduck-policy-vuln-find \
  --insecure \
  --out policy_candidate_projects.csv \
  --changes-out policy_candidate_changes.csv \
  --trigger-out policy_candidate_trigger.json \
  --cache policy_vuln_find_cache.json \
  --refresh-older-than-hours 6 \
  --workers 4 \
  --candidate-mode vulnerable-only \
  --progress-every 25 \
  --cache-save-every 100
```

`vulnerable-only` is the fastest default mode and checks only for the presence/count of vulnerable BOM components.

## Candidate modes

| Mode | Behavior |
|---|---|
| `vulnerable-only` | Checks vulnerable BOM component presence/count only. Fastest and default. |
| `policy-only` | Checks components with `policyStatus:IN_VIOLATION`. Policy-rule links are only followed when needed for requested policy filters. |
| `both` | Checks vulnerable components plus policy violation signals. This can be slower, especially when policy-rule traversal is enabled. |

If `--policy-name` or `--policy-rule-id` is supplied with `--candidate-mode vulnerable-only`, the finder automatically upgrades to `both` and prints a note.

## Scale and progress flags

| Flag | Default | Description |
|---|---:|---|
| `--workers` | `4` | Concurrent project-version candidate scans. Values greater than `8` are clamped to `8`. Use `1` for sequential behavior. |
| `--progress-every` | `25` | Print progress to stderr every N completed scans. |
| `--cache-save-every` | `100` | Save cache and partial output every N completed scans. |
| `--partial-out` | `<out>.partial` | Partial candidate CSV/JSON output path during scan. Disabled by default when `--out -` is used. |
| `--max-runtime-minutes` | unset | Stop scheduling additional scans after this runtime and write outputs for completed work. |
| `--skip-policy-rules` | off | Avoid following expensive `policy-rules` links during policy checks. Cannot be combined with `--policy-name` or `--policy-rule-id`. |

Example progress:

```text
Building project/version inventory...
Indexed 12,482 project version(s).
Loaded cache: 9,210 entrie(s).
Reusing 8,912 cached project version candidate scan(s); scanning 3,570.
Scanning with workers=4, candidate_mode=vulnerable-only.
[25/3570] scanned, candidates=4, failed=0, reused=8912, remaining=3545, elapsed=0m 32s
```

## Cache behavior

The cache is enabled by default.

```bash
--cache policy_vuln_find_cache.json
--refresh-older-than-hours 6
```

A cached entry is reused when:

- the project-version signature is unchanged
- the cache entry is not older than `--refresh-older-than-hours`
- the candidate mode and policy settings match the current run
- the prior entry did not fail, unless `--no-refresh-failed` is set
- the version has an update marker, unless `--trust-cache-without-update-marker` is set

The cache is saved incrementally every `--cache-save-every` completed scans and again at the end.

## Runtime cutoff

Use `--max-runtime-minutes` as a safety cutoff for scheduled jobs.

```bash
blackduck-policy-vuln-find \
  --max-runtime-minutes 20 \
  --trigger-out policy_candidate_trigger.json
```

When the cutoff is reached, the finder stops scheduling additional work, writes completed outputs, exits `0`, and includes trigger metadata such as:

```json
{
  "runtime_limited": true,
  "completed_count": 1000,
  "remaining_count": 11500
}
```

## Output

```bash
--out policy_candidate_projects.csv
--changes-out policy_candidate_changes.csv
--trigger-out policy_candidate_trigger.json
```

Main candidate CSV fields are preserved:

```text
project,project_version,project_phase,project_updated,
project_href,project_version_href,
candidate_reason,candidate_policy_name,candidate_policy_rule_href,
candidate_vulnerable_component_count,candidate_policy_violation_count,
candidate_security_violation_count,
candidate_detected_at,cache_entry_status,cache_reuse_reason,
scan_error,candidate_key,candidate_external_id
```

The trigger JSON includes operational metadata:

```json
{
  "inventory_count": 12482,
  "reused_count": 8912,
  "scanned_count": 3570,
  "failed_count": 3,
  "runtime_limited": false,
  "elapsed_seconds": 602.1,
  "candidate_mode": "vulnerable-only",
  "workers": 4
}
```

## Small test run

```bash
blackduck-policy-vuln-find \
  --insecure \
  --max-projects 5 \
  --max-versions 50 \
  --out policy_candidate_projects-test.csv \
  --changes-out policy_candidate_changes-test.csv \
  --trigger-out policy_candidate_trigger-test.json \
  --cache policy_vuln_find_cache-test.json \
  --refresh-all \
  --timeout 10 \
  --retries 0 \
  --page-limit 25 \
  --workers 4 \
  --candidate-mode vulnerable-only \
  --progress-every 10 \
  --cache-save-every 10
```

## Notes

- This finder does not collect full vulnerability findings.
- Use `policy_vuln_pull.py` for the detailed pull stage.
- No third-party Python packages are required.
