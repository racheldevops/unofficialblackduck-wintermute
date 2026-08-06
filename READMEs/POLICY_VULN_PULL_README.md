# Detailed candidate vulnerability pull

The blackduck-policy-vuln-pull command collects detailed findings for candidate project versions.

It uses the same shared collector as Jira and the cohort source.

## Default criteria

The compatibility Datadog profile uses:

    score greater than 8.9
    exploit availability required
    reachability optional

## Run

    blackduck-policy-vuln-pull \
      --candidates policy_candidate_projects.csv \
      --threshold 8.9 \
      --score-operator gt \
      --require-exploit-available \
      --workers 8 \
      --component-workers 2 \
      --page-limit 500 \
      --out policy_findings.csv \
      --failures-out policy_pull_failures.csv

## Enrichment

Findings can include:

- Severity and score
- Exploit availability
- Reachability
- Policy identity
- Component origin
- Black Duck resource links
- Stable candidate and finding identities

## Recovery

The puller supports:

| Feature | Purpose |
|---|---|
| Resume state | Skip completed candidates after interruption |
| Checkpoints | Persist state and partial findings |
| API cache | Reuse Black Duck responses |
| Runtime limit | Stop scheduling new work safely |
| Candidate workers | Collect several project versions concurrently |
| Component workers | Collect components concurrently inside a candidate |
| Shards | Split large candidate sets into subprocesses |

## Cohort consumer path

The cohort architecture normally performs broad source collection once. Datadog then filters the immutable cohort without calling Black Duck.

Use direct candidate pull for compatibility, diagnostics or standalone Datadog workflows.
