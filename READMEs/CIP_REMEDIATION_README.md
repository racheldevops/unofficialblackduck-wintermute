# Linux CIP remediation actions

Wintermute can use Linux CIP evidence to set project-scoped Black Duck vulnerability remediation status to PATCHED.

The workflow is dry-run-first and only creates actions when fix evidence is conclusive.

## Data flow

    Black Duck vulnerable Linux occurrence
        |
        v
    BDSA to CVE resolution
        |
        v
    cip-kernel-sec fixed-by evidence
        |
        v
    CIP tag commit containment
        |
        v
    Checksum-protected action plan
        |
        v
    Dry-run or confirmed apply

## Required environment

    BLACKDUCK_URL
    BLACKDUCK_API_TOKEN

Planning can access public CIP GitLab repositories without a token. Set these when authentication is required:

    GITLAB_TOKEN
    GITLAB_REST_URL

Apply mode requires a separate write-capable token:

    BLACKDUCK_ACTION_API_TOKEN

## Target discovery

Find a recent vulnerable Linux component:

    blackduck-wintermute-cip-discover --insecure

Discovery writes:

    .wintermute/blackduck/jobs/cip/discovery.json
    .wintermute/blackduck/jobs/cip/selected-target.env

Load the selected target for command-line use:

    set -a
    source .wintermute/blackduck/jobs/cip/selected-target.env
    set +a

The target environment contains:

    WINTERMUTE_CIP_PROJECT_VERSION_HREF
    WINTERMUTE_CIP_COMPONENT_VERSION_HREF
    WINTERMUTE_CIP_TAG
    WINTERMUTE_CIP_BRANCH

Multiple targets can be supplied with WINTERMUTE_CIP_TARGETS_JSON.

## Read-only endpoint probe

Verify the project-scoped remediation resource:

    blackduck-wintermute-actions-probe --insecure

The probe reads status and response shape. It does not write to Black Duck.

## Plan

Create a checksum-protected action plan:

    blackduck-wintermute-cip-plan --insecure

Plans are written under:

    .wintermute/blackduck/actions/plans/

Planning is bounded by occurrence, candidate, request, action and runtime limits. Cursors and evidence caches allow later runs to continue without loading the complete vulnerability collection.

## Combined dry run

The recommended scheduled command plans and executes a dry run:

    blackduck-wintermute-cip-job \
      --dry-run \
      --insecure \
      --max-occurrences-per-target 100 \
      --max-candidates-per-run 25 \
      --max-writes 10

Dry run rereads current remediation state and writes execution receipts without making Black Duck changes.

## Apply

Start with one write:

    blackduck-wintermute-cip-job \
      --apply \
      --confirm-apply \
      --insecure \
      --max-candidates-per-run 1 \
      --max-actions 1 \
      --max-writes 1

Apply behavior:

- Validates the plan and checksums
- Confirms the target Black Duck instance
- Rereads current state
- Rejects stale plans
- Preserves existing human remediation decisions
- Writes the PATCHED status and ownership comment
- Reads back and verifies the result
- Writes an execution receipt

## Artifacts

| Artifact | Purpose |
|---|---|
| plan.json | Immutable action plan |
| assessments.json | CIP evidence and decisions |
| cursors.json | Incremental target position |
| failures.json | Planning failures |
| checksums.json | Protected file digests |
| READY | Completed plan marker |
| result.json | Execution receipts |
| COMPLETE | Completed result marker |

## Request safety

Black Duck requests use shared pacing, retry and circuit-breaker controls.

Writes are not automatically retried because an interrupted mutation may have succeeded. The executor verifies state after each write attempt.

The action and planning locks include heartbeat, SIGTERM cleanup, stale-lock archival and dead local process recovery.

## TLS

Use a customer CA bundle in production:

    blackduck-wintermute-cip-job \
      --ca-bundle /path/to/customer-ca.pem

Use insecure mode only for controlled testing.

## Kubernetes

The separate suspended deployment is under:

    deploy/cip-actions/

It defaults to:

- Suspended schedule
- Dry-run mode
- Forbid concurrent jobs
- Zero Job retries
- Separate persistent storage
- Read-only planning credentials
- Optional write credentials
- Non-root and read-only container security

Review the target ConfigMap and Secrets before enabling the schedule.

## Validation

Read-only endpoint smoke:

    python scripts/run_cip_endpoint_smoke.py --insecure

Full pre-merge validation:

    python scripts/run_premerge_smoke.py --insecure

A successful smoke must report zero Black Duck writes.
