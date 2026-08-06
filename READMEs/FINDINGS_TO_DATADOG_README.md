# Datadog event publishing

The blackduck-findings-to-datadog command publishes normalized findings as Datadog Events.

It does not contact Black Duck.

## Authentication

Provide DATADOG_API_KEY through an approved secret manager or environment variable.

## Dry run

    blackduck-findings-to-datadog \
      --findings policy_findings.csv \
      --event-mode vulnerability \
      --site datadoghq.com \
      --service blackduck \
      --source blackduck \
      --env prod

Dry run is the default.

## Apply

    blackduck-findings-to-datadog \
      --findings policy_findings.csv \
      --event-mode vulnerability \
      --max-send 10 \
      --apply

Use max-send for the first controlled apply.

## Event modes

| Mode | Behavior |
|---|---|
| vulnerability | One summarized event per vulnerability; recommended default |
| project | One event per project group |
| finding | One event per direct finding |
| both | Project summary and finding events |

Vulnerability mode is usually the best on-call shape because one widespread vulnerability creates one summarized event rather than one event per occurrence.

## Event limits

| Option | Default |
|---|---:|
| event-project-limit | 25 |
| event-component-limit | 8 |
| event-finding-limit | 3 |
| event-vulnerability-link-limit | 3 |

## Resolution

Datadog Events are append-only. When an active finding or group disappears from the current input, Wintermute can send a recovery event and mark it resolved in local state.

Disable recovery events with no-send-resolved.

## State

Datadog state tracks:

- Active and resolved findings
- Project groups
- Vulnerability groups
- Event responses
- Last actions

Keep this state between runs.

## Cohort consumer

The consumer-only command verifies cohort checksums, applies Datadog criteria and publishes or plans events:

    blackduck-wintermute-datadog-cohort \
      --cohort /path/to/cohort \
      --dry-run \
      --strict

Datadog state remains separate from Jira and source state.
