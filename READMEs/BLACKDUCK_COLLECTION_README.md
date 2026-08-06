# Black Duck collection

The general Black Duck command collects normalized findings without coupling them to Jira or Datadog.

## Authentication

Set BLACKDUCK_URL and BLACKDUCK_API_TOKEN in the environment or load them from an approved secret manager.

For local macOS development:

    source scripts/load_blackduck_env.zsh

## General command

    blackduck-wintermute-pull --help

## Collection scopes

Collect parent-rollup children:

    blackduck-wintermute-pull \
      --scope parent-rollup \
      --resolve-bom-names \
      --workers 8 \
      --component-workers 2

Collect every project version:

    blackduck-wintermute-pull \
      --scope all-project-versions \
      --workers 8

Collect candidate versions:

    blackduck-wintermute-pull \
      --scope candidate-projects \
      --input policy_candidate_projects.csv

Collect explicit versions:

    blackduck-wintermute-pull \
      --scope explicit-project-versions \
      --input project-versions.json

Candidate and explicit scopes require CSV or JSON input.

## Output

The command writes:

- Normalized findings
- A collection manifest
- Scope and collection failures

Normalized findings retain source identity, component and vulnerability details, scores, exploitability, reachability, policies, custom fields and optional lineage contexts.

## Source criteria

The general pull supports:

| Option | Purpose |
|---|---|
| score-field | Black Duck score field |
| score-operator | Greater-than or greater-than-or-equal comparison |
| threshold | Numeric score threshold |
| require-exploit-available | Exclude findings without exploit evidence |
| require-reachable | Exclude findings without reachability evidence |
| policy-name | Require a named policy match |
| policy-rule-id | Require a policy-rule identity |
| workers | Concurrent project-version collection |
| component-workers | Concurrent component processing inside a target |

For reusable multi-destination cohorts, collect a broad superset and let destination consumers apply their own filters.

## TLS

Certificate verification is enabled by default.

Use a customer CA bundle in production:

    blackduck-wintermute-pull \
      --ca-bundle /path/to/customer-ca.pem

Use insecure mode only for controlled testing:

    blackduck-wintermute-pull --insecure

## Cohort source

The cohort source writes immutable, checksum-protected artifacts and a READY marker:

    blackduck-wintermute-cohort-source \
      --scope parent-rollup \
      --strict \
      --resolve-bom-names \
      --workers 8 \
      --component-workers 2

See COHORT_DEPLOYMENT_README.md for production orchestration.
