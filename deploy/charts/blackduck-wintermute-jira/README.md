# Wintermute Jira Helm deployment

This chart deploys Wintermute as a Kubernetes CronJob without Argo.

The GitLab job refreshes the registry Secret, runtime Secret, optional CA
ConfigMap, and Helm release. It does not build the container image.

## GitLab integration

Add this to the root GitLab configuration:

    include:
      - local: deploy/charts/blackduck-wintermute-jira/ci/gitlab-ci.example.yml

The parent pipeline must define a deploy stage.

## Required GitLab variables

These names match the original deployment contract.

### Cluster

    KUBECONFIG
    KUBE_NAMESPACE
    DEPLOY_TOOLS_IMAGE

KUBECONFIG should be a protected GitLab File variable unless the runner
already provides cluster access.

DEPLOY_TOOLS_IMAGE must contain helm, kubectl, python3, and POSIX sh.

### Private registry

    ARTIFACTORY_REGISTRY
    ARTIFACTORY_USERNAME
    ARTIFACTORY_PASSWORD
    IMAGE_REPOSITORY

ARTIFACTORY_REGISTRY is the registry hostname and optional port only.

IMAGE_REPOSITORY may use either of these forms:

    registry.example.invalid/team/wintermute
    registry.example.invalid/team/wintermute:existing-tag

When IMAGE_REPOSITORY has no tag, also configure:

    IMAGE_TAG

ARTIFACTORY_PASSWORD must be masked, hidden, protected, and scoped to the
deployment environment.

### Black Duck

    BLACKDUCK_URL
    BLACKDUCK_API_TOKEN

### Jira

    JIRA_URL
    JIRA_USER
    JIRA_API_TOKEN
    JIRA_PROJECT_KEY

BLACKDUCK_API_TOKEN and JIRA_API_TOKEN must be masked, hidden, protected, and
scoped to the deployment environment.

Do not enable CI_DEBUG_TRACE.

If protected variables are used, the develop branch must also be protected.

## Optional CA bundle

When Black Duck or Jira requires a corporate CA, configure:

    CA_BUNDLE_FILE

Create it as a protected GitLab File variable containing the complete PEM CA
bundle.

The pipeline creates or refreshes the CA ConfigMap automatically.

Registry certificate trust is separate. Kubernetes nodes and their container
runtime must already trust the private registry CA.

## Safe defaults

The included CI job defaults to:

    WINTERMUTE_IMAGE_PULL_POLICY=Always
    WINTERMUTE_IMAGE_PULL_SECRET=wintermute-registry-credentials
    WINTERMUTE_RUNTIME_SECRET=blackduck-wintermute-credentials

    WINTERMUTE_CREATE_NAMESPACE=false
    WINTERMUTE_PVC_SIZE=10Gi
    WINTERMUTE_STORAGE_CLASS=
    WINTERMUTE_CRON_SCHEDULE=0 2 * * *
    WINTERMUTE_TIME_ZONE=Europe/Berlin

    WINTERMUTE_CRON_SUSPEND=true
    WINTERMUTE_PIPELINE_MODE=dry-run
    WINTERMUTE_CONFIRM_APPLY=false
    WINTERMUTE_MAX_CREATE=10

    WINTERMUTE_WORKERS=2
    WINTERMUTE_PARENT_WORKERS=2
    WINTERMUTE_ROLLUP_WORKERS=2
    WINTERMUTE_PAGE_LIMIT=500

    WINTERMUTE_JIRA_VERIFY_TLS=true
    WINTERMUTE_BLACKDUCK_INSECURE=false

Set WINTERMUTE_CREATE_NAMESPACE=true only if the deployment identity may
create namespaces.

## Kubernetes resources managed by CI

The pipeline creates or refreshes:

    wintermute-registry-credentials
    blackduck-wintermute-credentials
    blackduck-wintermute-ca-bundle

The runtime Secret contains:

    BLACKDUCK_URL
    BLACKDUCK_API_TOKEN
    JIRA_URL
    JIRA_USER
    JIRA_API_TOKEN

Credential values are sent to Kubernetes over stdin and are not passed to
Helm.

## Initial deployment

Keep:

    WINTERMUTE_CRON_SUSPEND=true
    WINTERMUTE_PIPELINE_MODE=dry-run
    WINTERMUTE_CONFIRM_APPLY=false

Run the GitLab deployment job, then use Rancher Run Now and review the Pod
logs. No Jira issue should be created in dry-run mode.

## First bounded apply

After approving the dry run:

    WINTERMUTE_CRON_SUSPEND=true
    WINTERMUTE_PIPELINE_MODE=apply
    WINTERMUTE_CONFIRM_APPLY=true
    WINTERMUTE_MAX_CREATE=10

## Enable scheduling

Only after the bounded apply is accepted:

    WINTERMUTE_CRON_SUSPEND=false
    WINTERMUTE_PIPELINE_MODE=apply
    WINTERMUTE_CONFIRM_APPLY=true

## Persistent storage

The chart creates a 10Gi ReadWriteOnce PVC by default. It is retained during
Helm uninstall but is deleted if its namespace is deleted.

## Public repository privacy

Do not commit real customer registry hostnames, image paths, namespaces,
usernames, Jira URLs, Black Duck URLs, cluster names, or organization names.
