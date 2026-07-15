# findings_to_datadog.py

Publish normalized Black Duck high-risk vulnerability findings to Datadog Events.

## Auth

```bash
export DATADOG_API_KEY="..."
```

## Dry run

Dry run is the default unless `--apply` is supplied.

The default event mode is `vulnerability`, but it is shown explicitly here for clarity.

```bash
blackduck-findings-to-datadog \
  --findings policy_findings.csv \
  --event-mode vulnerability \
  --site datadoghq.com \
  --service blackduck \
  --source blackduck \
  --env prod \
  --state datadog-findings-state.json \
  --results-out datadog-publish-results.csv \
  --plan-out datadog-publish-plan.json
```

## Apply

```bash
blackduck-findings-to-datadog \
  --findings policy_findings.csv \
  --event-mode vulnerability \
  --site datadoghq.com \
  --service blackduck \
  --source blackduck \
  --env prod \
  --state datadog-findings-state.json \
  --results-out datadog-publish-results.csv \
  --plan-out datadog-publish-plan.json \
  --apply
```

## Safe smoke test

```bash
blackduck-findings-to-datadog \
  --findings policy_findings.csv \
  --event-mode vulnerability \
  --site datadoghq.com \
  --service blackduck \
  --source blackduck \
  --env prod \
  --max-send 10 \
  --apply
```

## Event modes

| Mode | Behavior |
|---|---|
| `vulnerability` | One summarized rollup event per CVE/vulnerability across all affected project versions. Default. |
| `project` | One grouped event per Black Duck project. |
| `finding` | One event per individual finding. |
| `both` | Project summary event plus finding detail events. |

## Vulnerability mode

```bash
--event-mode vulnerability
```

Vulnerability mode groups all current findings for the same CVE/vulnerability into one Datadog Event.

This is usually the best on-call shape for widespread vulnerabilities because one CVE affecting many projects produces one summarized event instead of one event per project or finding.

Example title:

```text
[Black Duck] CRITICAL CVE-2024-12345 affects 12 project version(s)
```

Example body shape:

```text
Black Duck vulnerability rollup event.

Vulnerability: CVE-2024-12345
Highest severity: CRITICAL
Active finding count: 37
Max score: 10.0
Affected project/version count: 12
Affected component count: 4
Critical count: 37
High count: 0
Medium count: 0
Low count: 0

Affected Black Duck project versions shown: 12 of 12
- service-a 1.2.3
- service-b 4.5.6

Affected components shown: 4 of 4
- openssl 1.0.2
- example-lib 3.1.4

Sample project/component findings shown: 3 of 37
- service-a 1.2.3 | openssl 1.0.2 | severity=CRITICAL | score=10.0
- service-b 4.5.6 | openssl 1.0.2 | severity=CRITICAL | score=10.0

Black Duck vulnerability links shown: 3 of 3
- https://blackduck.example.com/...

Event key: vulnerability_open:<vulnerability_group_external_id>
Aggregation key: bd_vulnerability_<vulnerability_group_external_id>
Note: Datadog Events have a small text cap, so this event is intentionally summarized.
```

Example tags:

```text
source:blackduck
service:blackduck
env:prod
bd_group:vulnerability
bd_vulnerability:cve-2024-12345
bd_severity:critical
bd_status:open
```

## Event body limits

Datadog Events have a small text cap, so vulnerability events intentionally include limited sections.

Defaults:

| Flag | Default | Description |
|---|---:|---|
| `--event-project-limit` | `25` | Maximum affected project/version rows in each vulnerability event. |
| `--event-component-limit` | `8` | Maximum affected component rows in each vulnerability event. |
| `--event-finding-limit` | `3` | Maximum sample project/component finding rows in each vulnerability event. |
| `--event-vulnerability-link-limit` | `3` | Maximum Black Duck vulnerability links in each vulnerability event. |

Example with larger sections:

```bash
blackduck-findings-to-datadog \
  --findings policy_findings.csv \
  --event-mode vulnerability \
  --event-project-limit 50 \
  --event-component-limit 12 \
  --event-finding-limit 5 \
  --event-vulnerability-link-limit 5 \
  --site datadoghq.com \
  --service blackduck \
  --source blackduck \
  --env prod
```

## Project mode

```bash
--event-mode project
```

Project mode sends one event per Black Duck project group.

It is useful when project ownership is more important than CVE-level aggregation.

Project event aggregation key:

```text
bd_project_<project_group_external_id>
```

## Finding mode

```bash
--event-mode finding
```

Finding mode sends one event per individual finding.

It is useful for detailed testing or low-volume environments. It can be noisy for widespread vulnerabilities.

Finding event aggregation key:

```text
bd_project_<project_group_external_id>
```

## Both mode

```bash
--event-mode both
```

Both mode sends:

```text
project summary event
finding detail events
```

It does not send vulnerability rollup events.

## Resolution behavior

Datadog Events are append-only. This tool treats closure as a recovery or success event.

### Vulnerability resolution

In `--event-mode vulnerability`, a vulnerability group is resolved when:

```text
vulnerability group was active in datadog-findings-state.json
but no current finding in the latest policy_findings.csv matches that vulnerability
```

Resolved vulnerability event title:

```text
[Black Duck] Resolved: CVE-2024-12345 no longer has matching exploitable high-risk findings
```

Resolved vulnerability event body:

```text
No current findings matched the configured Black Duck criteria for this vulnerability in the latest run.

Vulnerability group external ID: <vulnerability_group_external_id>
```

Resolved event tags include:

```text
bd_group:vulnerability
bd_status:resolved
```

### Project resolution

In `--event-mode project` or `--event-mode both`, a project group is resolved when:

```text
project_group_external_id was active in state
but has no active findings in the latest policy_findings.csv
```

### Finding resolution

In `--event-mode finding` or `--event-mode both`, a finding is resolved when:

```text
finding_external_id was active in state
but is missing from the latest policy_findings.csv
```

Use this flag to disable recovery events:

```bash
--no-send-resolved
```

## State

```text
datadog-findings-state.json
```

Tracks active and resolved findings, project groups, vulnerability groups, and Datadog event responses.

Important state sections:

```text
groups_by_external_id
findings_by_external_id
vulnerabilities_by_external_id
events_by_key
```

## Output files

```bash
--results-out datadog-publish-results.csv
--plan-out datadog-publish-plan.json
```

The results CSV records what was sent, skipped, or errored.

The plan JSON records planned event payloads and is useful for dry-run review.

## Useful operational flags

| Flag | Description |
|---|---|
| `--apply` | Actually send Datadog Events. Without this, the command is a dry run. |
| `--dry-run` | Force dry-run behavior. |
| `--refresh-existing` | Re-send events already active in local state. |
| `--max-send N` | Limit the number of events sent or planned. Useful for smoke tests. |
| `--progress-every N` | Print send progress every N planned events. Use `0` to disable. |
| `--checkpoint-every N` | Save Datadog state after every N sent events. Use `0` to save only at end. |
| `--fail-fast` | Stop after the first Datadog send error. |
| `--insecure` | Disable TLS certificate verification for Datadog HTTPS calls. Use only when required for lab/on-prem TLS inspection. |
| `--tags` | Comma-separated extra Datadog tags. |

Example with extra tags:

```bash
blackduck-findings-to-datadog \
  --findings policy_findings.csv \
  --event-mode vulnerability \
  --site datadoghq.com \
  --service blackduck \
  --source blackduck \
  --env prod \
  --tags team:appsec,owner:security
```

## Datadog endpoint

```text
POST https://api.<site>/api/v1/events
```

Examples:

```text
https://api.datadoghq.com/api/v1/events
https://api.us3.datadoghq.com/api/v1/events
https://api.datadoghq.eu/api/v1/events
```

Auth header:

```text
DD-API-KEY: <DATADOG_API_KEY>
```
