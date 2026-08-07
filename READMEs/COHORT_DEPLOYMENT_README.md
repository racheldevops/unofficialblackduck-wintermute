# Cohort deployment

The recommended production model uses three independently scoped images:

    Black Duck source
        |
        v
    Immutable cohort
        |
        v
    Jira consumer
        |
        v
    Datadog consumer

Datadog is configured to continue after a Jira failure. Processing remains sequential so the deployment is portable with ReadWriteOnce storage.

## Images

| Image | Responsibility |
|---|---|
| blackduck-wintermute-source | Black Duck inventory, lineage, collection and cohort creation |
| blackduck-wintermute-jira | Jira filtering, hierarchy planning and publishing |
| blackduck-wintermute-datadog | Datadog filtering, event planning and publishing |

All images are built from the same tested wheel.

## Credentials

Use separate Secrets:

| Secret | Contents |
|---|---|
| blackduck-wintermute-blackduck-credentials | BLACKDUCK_URL and BLACKDUCK_API_TOKEN |
| blackduck-wintermute-jira-credentials | JIRA_URL and Jira credentials |
| blackduck-wintermute-datadog-credentials | DATADOG_API_KEY |
| blackduck-wintermute-registry | Private registry authentication |

Never combine destination credentials into the source Secret.

## Storage

| Claim | Purpose |
|---|---|
| blackduck-wintermute-cohorts | Immutable cohort artifacts |
| blackduck-wintermute-source-data | Source cache and state |
| blackduck-wintermute-jira-data | Jira state and output |
| blackduck-wintermute-datadog-data | Datadog state and output |

Consumers mount cohort storage read-only.

## Prerequisites

- Kubernetes
- Argo Workflows
- Workflow, WorkflowTemplate and CronWorkflow CRDs
- Private registry access
- Storage classes for the four claims
- Destination-specific Secrets
- Customer Jira configuration
- Customer CA bundle where required

## Build

    docker build --target source \
      -t blackduck-wintermute-source:local .

    docker build --target jira \
      -t blackduck-wintermute-jira:local .

    docker build --target datadog \
      -t blackduck-wintermute-datadog:local .

## Render

    python scripts/render_cohort_manifest.py \
      --registry-host registry.example.com \
      --registry-repository security/blackduck-wintermute \
      --image-tag COMMIT_SHA \
      --namespace blackduck-wintermute \
      --jira-mode dry-run \
      --datadog-mode dry-run \
      --output rendered-cohort-manifest.yaml

The renderer rejects latest, replace-me and unconfirmed apply mode.

## Cluster preflight

    python scripts/validate_cohort_cluster.py \
      --manifest rendered-cohort-manifest.yaml \
      --namespace blackduck-wintermute \
      --require-secrets

Preflight checks CRDs, namespace, Secret existence, deployment permissions and a server-side dry run. It never reads Secret values.

## Deploy

Review the diff:

    kubectl diff \
      --filename rendered-cohort-manifest.yaml

Apply the suspended dry-run deployment:

    kubectl apply \
      --server-side \
      --field-manager blackduck-wintermute-cohort \
      --filename rendered-cohort-manifest.yaml

The CronWorkflow is suspended and both consumers use dry-run by default.

## Manual workflow

    argo submit \
      --namespace blackduck-wintermute \
      --from workflowtemplate/blackduck-wintermute-cohort \
      --parameter jira-mode=dry-run \
      --parameter datadog-mode=dry-run \
      --parameter confirm-apply=false \
      --watch

## Apply mode

Apply mode requires explicit confirmation:

    python scripts/render_cohort_manifest.py \
      --registry-host registry.example.com \
      --registry-repository security/blackduck-wintermute \
      --image-tag COMMIT_SHA \
      --namespace blackduck-wintermute \
      --jira-mode apply \
      --datadog-mode apply \
      --confirm-apply \
      --output rendered-cohort-manifest.yaml

Keep the schedule suspended until a manually submitted apply run is accepted.

## Retention and integrity

Cohorts contain normalized findings, manifests, failures and checksums. READY is written last.

Consumers reject:

- Missing READY markers
- Unsupported schemas
- Missing checksums
- Modified artifacts
- Strict cohorts containing collection failures

The source retains ten cohorts by default. Configure retain-cohorts to match audit and storage requirements.

## Automation

Image workflow:

    .github/workflows/cohort-container-build.yml

Deployment workflow:

    .github/workflows/cohort-kubernetes-deploy.yml

Deployment operations are render, diff and apply. Production environments should require approval.

## Optional destinations

Jira and Datadog can each be set to disabled, dry-run, or apply.

For Jira only:

    --jira-mode dry-run
    --datadog-mode disabled

For Datadog only:

    --jira-mode disabled
    --datadog-mode dry-run

When a destination is disabled, its Pod is skipped, its API credentials are not required, and its state is not modified. The finalizer records the destination as disabled and still completes the cohort lifecycle.
