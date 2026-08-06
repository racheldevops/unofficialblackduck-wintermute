# Kubernetes deployment

Deploy the Black Duck Wintermute Jira pipeline as a finite Kubernetes CronJob.

The container runs the Jira pipeline once and exits. Kubernetes controls the schedule, retries, concurrency, and Pod lifecycle.

## Runtime model

Each scheduled run:

    CronJob schedule
        |
        v
    New Kubernetes Job and Pod
        |
        v
    Mount persistent storage, configuration, CA, and secrets
        |
        v
    Run blackduck-jira-pipeline
        |
        v
    Write updated cache, state, plans, and results
        |
        v
    Exit
        |
        v
    Persistent volume remains for the next run

The application is not a permanent HTTP service.

## Pipeline stages

The container entry point runs:

    blackduck-find-parents
        |
        v
    blackduck-vuln-rollup
        |
        v
    blackduck-hierarchy-plan
        |
        v
    blackduck-findings-to-jira

The orchestration module is:

    wintermute.jira.pipeline

Installed command:

    blackduck-jira-pipeline

Dry run is the default.

## Container image

Build locally:

    docker build \
      --tag blackduck-wintermute:local \
      --file Dockerfile \
      .

Show pipeline help:

    docker run \
      --rm \
      blackduck-wintermute:local \
      --help

The image:

- Uses Python 3.12.10.
- Uses a multi-stage build.
- Installs the project wheel.
- Runs as user and group 10001.
- Uses a non-root user.
- Supports a read-only root filesystem.
- Writes runtime data under the mounted output directory.
- Contains no credentials or customer CA certificate.

## Persistent storage

Kubernetes CronJob Pods do not preserve their own writable filesystem after completion.

The deployment creates a PersistentVolumeClaim named:

    blackduck-wintermute-data

It is mounted at:

    /var/lib/blackduck-wintermute

The container sets:

    WINTERMUTE_OUTPUT_DIR=/var/lib/blackduck-wintermute

The PVC preserves:

    jira/parent_projects.csv
    jira/parent_project_changes.csv
    jira/findings.csv
    jira/jira-hierarchy-plan.json
    jira/jira-rollup-plan.json
    jira/jira-rollup-results.csv
    jira/pipeline-run-summary.json
    jira/cache/parent_projects_cache.json
    jira/cache/subp_vuln_rollup_cache.json
    jira/state/jira-rollup-state.json
    jira/runs/

The PVC survives:

- Pod completion
- Job deletion
- CronJob updates
- Container image updates
- Normal deployment changes

Deleting the PVC may delete the underlying data, depending on the storage class reclaim policy.

Do not delete the PVC during normal upgrades.

## Storage class

The base PVC uses the cluster’s default storage class.

To select a customer storage class, update or apply the example patch:

    deploy/overlays/customer/pvc-storage-class-patch.yaml.example

Required customer value:

    storageClassName

Recommended initial capacity:

    5Gi

Recommended access mode:

    ReadWriteOnce

The CronJob uses concurrencyPolicy Forbid, so one writer is expected.

## Cache behavior across runs

The parent discovery cache stores relationship scans by parent project-version identity.

The vulnerability rollup cache stores Black Duck API responses with expiry metadata.

The Jira state stores:

- Hierarchy external IDs
- Jira issue keys
- Lookup labels
- Link state
- First and last seen times
- Last actions

Because all three are on the PVC, later Jobs reuse previous state.

The second run should therefore be faster and should not create duplicate Jira issues.

## Run directories

Each pipeline execution creates a run-specific directory:

    /var/lib/blackduck-wintermute/jira/runs/RUN_ID/

Run directories contain staged outputs and diagnostics.

Only after required stages succeed are selected files promoted into:

    /var/lib/blackduck-wintermute/jira/

The active pipeline summary is:

    /var/lib/blackduck-wintermute/jira/pipeline-run-summary.json

The default run retention is ten run directories.

Change it with:

    --retain-runs NUMBER

## Strict mode

Strict mode is the default.

When parent discovery or vulnerability rollup reports failed relationships:

- Jira publishing is skipped.
- Diagnostics remain in the run directory.
- The Job exits nonzero.
- Previous active outputs remain available.

Explicit strict mode:

    blackduck-jira-pipeline --strict

Allow partial processing only when intentionally required:

    blackduck-jira-pipeline --allow-partial

Partial mode should not be used for unattended production publishing without customer approval.

## Concurrency

The CronJob sets:

    concurrencyPolicy: Forbid

This prevents overlapping scheduled Jobs.

The pipeline also uses a lock file:

    /var/lib/blackduck-wintermute/jira/pipeline.lock

The lock contains:

- Run ID
- Token
- Hostname
- Pod name
- Process ID
- Start time

The Kubernetes setting is the primary protection. The lock is defense in depth for manual or direct executions.

## Kubernetes files

Base resources:

    deploy/base/pvc.yaml
    deploy/base/cronjob.yaml
    deploy/base/kustomization.yaml
    deploy/base/jira-rollup-config.json

Customer overlay:

    deploy/overlays/customer/

Examples:

    deploy/examples/credentials-secret.example.yaml
    deploy/examples/customer-ca-configmap.example.yaml
    deploy/examples/customer-ca-patch.example.yaml
    deploy/examples/pvc-storage-class-patch.example.yaml

The base and customer overlay are suspended and use dry-run mode by default.

## Render the manifests

Render the base:

    kubectl kustomize deploy/base

Render the customer overlay:

    kubectl kustomize deploy/overlays/customer

Render to a file:

    kubectl kustomize deploy/overlays/customer \
      > rendered-manifest.yaml

Review the rendered file before applying it.

## Customer overlay configuration

Before deployment, update:

    deploy/overlays/customer/kustomization.yaml

Replace:

    registry.invalid/customer/blackduck-wintermute

with the private registry and repository.

Replace:

    replace-me

with an immutable image tag, normally a commit SHA.

Also update:

    deploy/overlays/customer/jira-rollup-config.json

Set at least:

- Jira project key
- Jira URL if not supplied through JIRA_URL
- Authentication mode
- Jira custom-field IDs
- Entity field mapping
- Project Name field mapping
- Project Version field mapping
- CVSS vector field mapping
- CVSS score field mapping

Do not place credentials in this ConfigMap.

## Private registry build variables

The image build workflow uses GitHub repository or environment variables:

    REGISTRY_HOST
    REGISTRY_REPOSITORY

It uses GitHub secrets:

    REGISTRY_USERNAME
    REGISTRY_PASSWORD

The resulting image is:

    REGISTRY_HOST/REGISTRY_REPOSITORY:COMMIT_SHA

Production deployments should use an immutable commit SHA or image digest.

## Private registry image pull secret

Create the namespace first:

    kubectl create namespace blackduck-wintermute

Create the image pull secret:

    kubectl create secret docker-registry \
      blackduck-wintermute-registry \
      --namespace blackduck-wintermute \
      --docker-server PRIVATE_REGISTRY_HOST \
      --docker-username REGISTRY_USERNAME \
      --docker-password REGISTRY_PASSWORD

Do not store the real registry password in repository files.

## Runtime credential secret

Create a Jira and Black Duck credential secret:

    kubectl create secret generic \
      blackduck-wintermute-credentials \
      --namespace blackduck-wintermute \
      --from-literal BLACKDUCK_URL=https://blackduck.example.com \
      --from-literal BLACKDUCK_API_TOKEN=REPLACE_ME \
      --from-literal JIRA_URL=https://jira.example.com \
      --from-literal JIRA_USER=REPLACE_ME \
      --from-literal JIRA_API_TOKEN=REPLACE_ME

For Jira bearer authentication, use JIRA_PAT and configure auth_mode as bearer.

Prefer External Secrets, Vault, or a cloud secret manager when available.

## Customer TLS certificate

Production should not use insecure TLS.

Ask the customer for the issuing root and intermediate CA bundle.

Create the CA ConfigMap:

    kubectl create configmap \
      blackduck-wintermute-ca \
      --namespace blackduck-wintermute \
      --from-file customer-ca.pem=/path/to/customer-ca.pem

The CronJob mounts it at:

    /etc/blackduck-wintermute/ca/customer-ca.pem

Enable the CA pipeline argument:

    --ca-bundle
    /etc/blackduck-wintermute/ca/customer-ca.pem

Set:

    SSL_CERT_FILE=/etc/blackduck-wintermute/ca/customer-ca.pem

An example patch is provided under the customer overlay and examples directories.

Do not use a short-lived leaf server certificate as the trust bundle.

## CronJob defaults

The base CronJob uses:

    schedule: 0 2 * * *
    timeZone: Etc/UTC
    suspend: true
    concurrencyPolicy: Forbid
    successfulJobsHistoryLimit: 3
    failedJobsHistoryLimit: 5
    backoffLimit: 1
    activeDeadlineSeconds: 21600

The CronJob remains suspended until explicitly enabled.

The container defaults to:

    --dry-run
    --strict

## GitHub Actions image build

Workflow:

    .github/workflows/container-build.yml

The workflow:

1. Installs the Python package.
2. Compiles the source.
3. Runs pytest.
4. Builds the image.
5. Logs in to the private registry.
6. Pushes the commit-SHA image.
7. Records the image digest.

It runs for main branch changes, version tags, and manual dispatch.

## GitHub Actions deployment

Workflow:

    .github/workflows/kubernetes-deploy.yml

The deployment workflow is manual only.

Available operations:

| Operation | Behavior |
|---|---|
| render | Render and upload the manifest without cluster access |
| diff | Compare the rendered manifest with the cluster |
| apply | Apply the rendered resources to the cluster |

Available pipeline modes:

| Mode | Behavior |
|---|---|
| dry-run | CronJob builds Jira plans but does not change Jira |
| apply | CronJob can create or update Jira issues |

Deploying apply mode requires confirm_apply to be true.

GitHub environment variables:

    REGISTRY_HOST
    REGISTRY_REPOSITORY
    KUBE_NAMESPACE
    CRON_SCHEDULE
    CRON_TIMEZONE

GitHub environment secrets:

    KUBE_CONFIG_B64

The kubeconfig must be base64 encoded.

The deployment environment should use GitHub environment approval for production.

## Initial deployment sequence

1. Create the namespace.
2. Create the private registry pull secret.
3. Create the runtime credential secret.
4. Add the customer CA ConfigMap when available.
5. Configure Jira custom-field IDs.
6. Build and push an image.
7. Run the deployment workflow with operation render.
8. Review the rendered manifest.
9. Run operation diff.
10. Run operation apply with pipeline mode dry-run.
11. Manually trigger the suspended CronJob.
12. Review logs and persistent output.
13. Trigger it a second time and verify cache reuse.
14. Run a limited Jira apply.
15. Enable the schedule after customer acceptance.

## Apply the customer overlay manually

After replacing all placeholders:

    kubectl apply \
      --server-side \
      --field-manager blackduck-wintermute \
      --kustomize deploy/overlays/customer

The first deployment should remain suspended and dry-run only.

## Manual Job execution

Create a one-time Job from the CronJob:

    run_id=$(date -u +%Y%m%d%H%M%S)

    kubectl create job \
      --namespace blackduck-wintermute \
      --from=cronjob/blackduck-jira-pipeline \
      blackduck-jira-manual-${run_id}

Watch the Job:

    kubectl get jobs \
      --namespace blackduck-wintermute \
      --watch

View Pods:

    kubectl get pods \
      --namespace blackduck-wintermute

View logs:

    kubectl logs \
      --namespace blackduck-wintermute \
      job/blackduck-jira-manual-RUN_ID \
      --follow

## Inspect persistent data

Create a temporary inspection Pod or use an approved storage inspection process.

Important paths:

    /var/lib/blackduck-wintermute/jira/pipeline-run-summary.json
    /var/lib/blackduck-wintermute/jira/jira-rollup-plan.json
    /var/lib/blackduck-wintermute/jira/jira-rollup-results.csv
    /var/lib/blackduck-wintermute/jira/cache/
    /var/lib/blackduck-wintermute/jira/state/
    /var/lib/blackduck-wintermute/jira/runs/

Do not edit state files while a Job is running.

## Limited Jira apply

After dry-run approval, configure:

    --apply
    --strict
    --max-create
    5

Keep the CronJob suspended and create a manual Job first.

Verify:

- CVE Epic issue type
- Project/version Task issue type
- Task parent relationship
- Task title
- Component display version
- CVSS rendering
- Entity custom field
- BDAlert label
- Human-readable vulnerability label
- Deterministic lookup label
- Persistent Jira state

## Enabling the schedule

Only after acceptance:

1. Change the pipeline argument from dry-run to apply if required.
2. Confirm customer approval.
3. Set suspend to false.
4. Confirm schedule and timezone.
5. Apply the updated overlay.
6. Monitor the first scheduled Job.

## Failure troubleshooting

Inspect Job status:

    kubectl describe job \
      --namespace blackduck-wintermute \
      JOB_NAME

Inspect Pod events:

    kubectl describe pod \
      --namespace blackduck-wintermute \
      POD_NAME

Inspect logs:

    kubectl logs \
      --namespace blackduck-wintermute \
      POD_NAME

Inspect the active run summary on the PVC:

    jira/pipeline-run-summary.json

Common exit codes:

| Code | Meaning |
|---:|---|
| 0 | Pipeline succeeded |
| 1 | Partial or stage failure |
| 2 | Invalid arguments or configuration |
| 3 | Required output missing |
| 4 | Concurrent-run lock conflict |
| 5 | Strict mode rejected partial data |
| 130 | Interrupted |

## Stale lock handling

The default lock stale period is eight hours.

If a Pod was forcefully terminated, inspect:

    jira/pipeline.lock

Do not remove an active lock.

If no Pod or Job is active and the lock is confirmed stale, archive or remove it before retrying.

The pipeline automatically archives locks older than the configured stale interval.

## PVC backup and recovery

Confirm the storage class reclaim policy before production.

Recommended protections:

- Volume snapshots
- Scheduled PVC backups
- Retention protection
- Restricted PVC deletion permissions
- Restore testing

The Jira state file is important for efficient deduplication, but Jira can also be searched using deterministic labels.

After restoring an older state snapshot, use Jira reconciliation:

    --refresh-existing-jira
    --sync-existing-fields

## Updating the image

Build and push a new immutable image tag.

Run deployment operation render and diff.

Apply the new image while keeping the PVC unchanged.

The new Pod will mount the existing caches and state.

Do not replace or recreate the PVC during normal image upgrades.

## Rollback

To roll back:

1. Select a previously approved immutable image tag.
2. Render the deployment.
3. Review the diff.
4. Apply the previous image.
5. Keep the same PVC.
6. Monitor the next manual Job.

Application state should normally remain forward-compatible within the same release line. Back up the PVC before significant schema changes.

## Security checklist

Before production:

- Image runs as non-root.
- Root filesystem is read-only.
- All Linux capabilities are dropped.
- Privilege escalation is disabled.
- Service account token mounting is disabled.
- Customer CA validation is enabled.
- Insecure TLS is not used.
- Registry credentials are in an image pull secret.
- Runtime credentials are in a Secret or external secret manager.
- Jira config contains no credentials.
- Immutable image tags are used.
- CronJob concurrency is forbidden.
- PVC deletion is restricted.
- Production deployment uses approval.

## No liveness probe

A liveness probe is not required because the workload is a finite Job.

Kubernetes determines success from the process exit code.

The active deadline protects against indefinitely running Jobs.
