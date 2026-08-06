# Jira publishing

The blackduck-findings-to-jira command publishes a generated hierarchy plan or direct flat findings into Jira.

Hierarchy publishing is recommended.

## Authentication

Basic authentication uses:

    JIRA_URL
    JIRA_USER
    JIRA_API_TOKEN

Bearer authentication uses JIRA_PAT and Jira auth mode bearer.

If Jira connection details are incomplete, the publisher falls back to dry-run mode.

## Dry run

    blackduck-findings-to-jira \
      --hierarchy-plan jira-hierarchy-plan.json \
      --config src/wintermute/jira/config/jira-rollup-config.json \
      --dry-run

Dry run writes the complete Jira payload plan without changing Jira.

## Apply

    blackduck-findings-to-jira \
      --hierarchy-plan jira-hierarchy-plan.json \
      --config src/wintermute/jira/config/jira-rollup-config.json \
      --max-create 5 \
      --apply

Use max-create for the first controlled apply.

## Hierarchy order

Nodes are processed in dependency order:

1. Epic
2. Task or Story
3. Vulnerability issue when project-lineage mode is used

## Parent modes

| Mode | Behavior |
|---|---|
| jira_parent | Sends the Jira parent field |
| issue_link | Creates a configured Jira issue link |
| epic_link_field | Sets a configured Epic Link field |

## Existing issues

Wintermute uses deterministic labels and local state to avoid duplicate creation.

Useful options:

| Option | Purpose |
|---|---|
| refresh-existing | Reconcile local state with Jira |
| sync-existing-fields | Update configured managed fields |
| max-create | Limit creations in an apply run |
| description-format | Select wiki or Atlassian Document Format |

## Cohort consumer

The consumer-only command reads a checksum-verified cohort and does not contact Black Duck:

    blackduck-wintermute-jira-cohort \
      --cohort /path/to/cohort \
      --dry-run \
      --strict \
      --config src/wintermute/jira/config/jira-rollup-config.json

The default cohort hierarchy is vulnerability-remediation.

## State

Keep Jira state between runs. It records issue keys, external identities, lookup labels and link state.

Jira state is destination-specific and must not be shared with Datadog.
