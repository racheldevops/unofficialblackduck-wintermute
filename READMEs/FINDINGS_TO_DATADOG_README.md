# findings_to_datadog.py

Publish normalized Black Duck high-risk vulnerability findings to Datadog Events.

## Auth

    export DATADOG_API_KEY="..."

## Dry run

    blackduck-findings-to-datadog \
      --findings policy_findings.csv \
      --event-mode project \
      --site datadoghq.com \
      --service blackduck \
      --source blackduck \
      --env prod

## Apply

    blackduck-findings-to-datadog \
      --findings policy_findings.csv \
      --event-mode project \
      --site datadoghq.com \
      --service blackduck \
      --source blackduck \
      --env prod \
      --apply

## Event modes

- project: one grouped event per project. Default.
- finding: one event per finding.
- both: project summary plus finding detail events.

## Resolution behavior

Datadog Events are append-only. This tool treats closure as a recovery or success event.

A finding is resolved when it was active in datadog-findings-state.json but is missing from the latest policy_findings.csv.

A project group is resolved when it no longer has active findings.

Use --no-send-resolved to disable recovery events.

## State

    datadog-findings-state.json

Tracks active and resolved findings, groups, and Datadog event responses.
