# Jira hierarchy planning

The blackduck-hierarchy-plan command converts rollup findings into deterministic Jira hierarchy nodes.

It does not call Black Duck or Jira.

## Recommended mode

The default mode is vulnerability-remediation:

    Vulnerability Epic
        |
        +--> Affected project-version Task

Run:

    blackduck-hierarchy-plan \
      --findings findings.csv \
      --hierarchy-mode vulnerability-remediation \
      --plan-out jira-hierarchy-plan.json \
      --summary-out jira-hierarchy-summary.csv \
      --nodes-out jira-hierarchy-nodes.csv

## Project-lineage mode

The alternative project-lineage mode represents Black Duck structure directly:

    Parent project-version Epic
        |
        +--> Child project-version Story
                 |
                 +--> Vulnerability issue

Run:

    blackduck-hierarchy-plan \
      --findings findings.csv \
      --hierarchy-mode project-lineage

Compatibility aliases remain accepted:

| Alias | Canonical mode |
|---|---|
| vulnerability-project | vulnerability-remediation |
| project-subproject-vulnerability | project-lineage |

New plans emit canonical names.

## Deterministic identities

Vulnerability-remediation grouping uses:

- One Epic per vulnerability
- One Task per vulnerability and affected project version

Display titles, Entity values, component summaries and Jira field configuration do not change deterministic IDs.

## Filtering

Apply filters before grouping:

    blackduck-hierarchy-plan \
      --findings findings.csv \
      --only-parent-project "Product" \
      --only-parent-version "1.0" \
      --only-subproject "Service" \
      --only-vulnerability "CVE-2026-0001"

Required ancestor nodes are retained.

## Outputs

| File | Purpose |
|---|---|
| jira-hierarchy-plan.json | Complete reusable plan |
| jira-hierarchy-summary.csv | Epic and Task summary |
| jira-hierarchy-nodes.csv | Flattened node inventory |

The Jira publisher applies final issue types, titles, priorities, managed fields and parent relationships.
