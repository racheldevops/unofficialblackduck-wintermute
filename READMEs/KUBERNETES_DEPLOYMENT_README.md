# Kubernetes deployment

Wintermute supports two Kubernetes models.

## Recommended cohort deployment

The cohort model separates source collection from destination delivery:

    Source image
        |
        v
    Immutable cohort
        |
        v
    Jira image
        |
        v
    Datadog image

It uses Argo Workflows and separate PVCs for cohort artifacts, source state, Jira state and Datadog state.

Start with:

    READMEs/COHORT_DEPLOYMENT_README.md

Key resources:

    deploy/cohort/
    deploy/overlays/customer-cohort/

Render:

    kubectl kustomize deploy/cohort

    kubectl kustomize \
      deploy/overlays/customer-cohort

For immutable customer rendering, use:

    python scripts/render_cohort_manifest.py --help

For cluster preflight, use:

    python scripts/validate_cohort_cluster.py --help

## Compatibility Jira CronJob

The original all-in-one Jira pipeline remains available:

    deploy/base/
    deploy/overlays/customer/

It runs:

    Parent discovery
        |
        v
    Parent vulnerability rollup
        |
        v
    Jira hierarchy planning
        |
        v
    Jira publishing

The CronJob is suspended and uses dry-run by default.

## Compatibility resources

The default compatibility Pod uses:

- Eight parent workers
- Eight rollup workers
- One CPU request
- Four CPU limit
- One GiB memory request
- Four GiB memory limit
- Non-root UID and GID 10001
- Read-only root filesystem
- Dropped capabilities
- Disabled service-account token
- ReadWriteOnce persistent storage

## Security

Before production:

- Use immutable image tags
- Use destination-scoped Secrets
- Use a customer CA bundle
- Do not use insecure TLS
- Keep schedules suspended during acceptance
- Review dry-run plans
- Require deployment approval
- Protect PVC deletion
- Back up destination state
- Validate Argo CRDs and RBAC

## Apply safety

Cohort destination apply mode requires confirm-apply=true.

Compatibility Jira apply mode should first use a small max-create limit and a manually triggered Job.

## Validation

Run:

    python -m pytest -q tests

    python scripts/validate_entrypoints.py \
      --require-installed

    python scripts/validate_release.py \
      --build \
      --image blackduck-wintermute:local

    zsh scripts/run_cohort_smoke.zsh

The smoke test verifies source creation, cohort checksums, Jira dry run and Datadog dry run on one shared volume.
