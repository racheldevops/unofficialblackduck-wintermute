# Kubernetes deployment

Wintermute supports cohort, compatibility Jira, SCM, and CIP action deployments.

## Cohort deployment

The recommended vulnerability-delivery model separates source collection from destination delivery:

    Source image
        |
        v
    Immutable cohort
        |
        +--> Jira
        |
        +--> Datadog
        |
        +--> Optional read-only SCM coverage

Start with:

    READMEs/COHORT_DEPLOYMENT_README.md

Resources:

    deploy/cohort/
    deploy/overlays/customer-cohort/

Render:

    python scripts/render_cohort_manifest.py --help

Validate cluster prerequisites:

    python scripts/validate_cohort_cluster.py --help

## SCM coverage

The SCM image supports read-only GitHub and GitLab inventory.

Customers using both providers should run them sequentially with separate provider snapshots:

    python scripts/run_scm_multi_provider.py \
      --insecure \
      --collect-direct-scan-evidence

SCM coverage does not modify repositories or Black Duck.

See:

    READMEs/SCM_COVERAGE_README.md

## CIP actions

The CIP action deployment is independent from cohort delivery:

    deploy/cip-actions/

It contains:

- Suspended CronJob
- Dry-run default
- Forbid concurrency policy
- Zero Job retries
- Separate persistent storage
- ConfigMap-driven targets
- Separate planning and action credentials
- Request, runtime and write limits

Render:

    kubectl kustomize deploy/cip-actions

Review and apply:

    kubectl diff --filename rendered-cip.yaml
    kubectl apply --filename rendered-cip.yaml

Keep the schedule suspended until dry-run and one-write acceptance are complete.

See:

    READMEs/CIP_REMEDIATION_README.md

## Compatibility Jira CronJob

The original all-in-one Jira pipeline remains available:

    deploy/base/
    deploy/overlays/customer/

It runs parent discovery, vulnerability rollup, hierarchy planning, and Jira publishing.

The CronJob is suspended and uses dry-run by default.

## Security defaults

Production deployments should use:

- Immutable image tags
- Destination-scoped Secrets
- Customer CA bundles
- Suspended schedules during acceptance
- Dry-run plans before apply
- Non-root containers
- Read-only root filesystems
- Dropped capabilities
- Disabled service-account tokens
- Persistent state and protected PVC deletion

Do not use insecure TLS in production.

## Validation

Run:

    python -m pytest -q tests
    python scripts/validate_entrypoints.py
    python scripts/validate_release.py --skip-docker

Read-only endpoint validation:

    python scripts/run_premerge_smoke.py --insecure

Use a CA bundle instead of insecure mode for production acceptance.
