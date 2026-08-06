# Candidate project discovery

The blackduck-policy-vuln-find command identifies Black Duck project versions worth passing to detailed vulnerability collection.

It remains a compatibility workflow over shared Wintermute inventory and candidate services.

## Candidate modes

| Mode | Behavior |
|---|---|
| vulnerable-only | Checks whether vulnerable BOM components exist |
| policy-only | Checks components in policy violation |
| both | Combines vulnerable component and policy signals |

Supplying a policy name or rule automatically requires policy-aware collection.

## Run

    blackduck-policy-vuln-find \
      --candidate-mode vulnerable-only \
      --workers 8 \
      --page-limit 500 \
      --out policy_candidate_projects.csv \
      --changes-out policy_candidate_changes.csv \
      --trigger-out policy_candidate_trigger.json

## Outputs

| Output | Purpose |
|---|---|
| Candidate CSV or JSON | Project versions for detailed collection |
| Change report | Added, removed and changed candidates |
| Trigger JSON | Whether downstream collection should run |
| Cache | Per-project-version candidate decisions |

## Scale and resilience

The finder supports:

- Concurrent inventory and candidate checks
- Incremental cache reuse
- Periodic cache checkpoints
- Partial output
- Runtime cutoffs
- Retry of previous failures

Useful options:

    --workers 8
    --progress-every 25
    --cache-save-every 100
    --max-runtime-minutes 20

## Shared cohort alternative

Candidate rows can feed the general collector:

    blackduck-wintermute-pull \
      --scope candidate-projects \
      --input policy_candidate_projects.csv

For scheduled multi-destination operation, prefer an immutable cohort.
