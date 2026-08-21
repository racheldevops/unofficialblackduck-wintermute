# Wintermute Jira Helm deployment

This chart deploys Wintermute as a Kubernetes CronJob without Argo.

The GitLab job manages only the Helm release. The namespace and application
Secrets must already exist in Rancher. It does not build the application image,
create a namespace, or create credentials.

## GitLab integration

Add this to the root GitLab configuration:

    include:
      - local: deploy/charts/blackduck-wintermute-jira/ci/gitlab-ci.example.yml

The parent pipeline must define a deploy stage.

## Deployment tools image

DEPLOY_TOOLS_IMAGE must contain:

    Helm 3
    POSIX shell
    CA certificates

It does not need kubectl or Python.

Helm connects directly to the Kubernetes API using KUBECONFIG.

## Required GitLab variables

### Kubernetes

    KUBECONFIG
    KUBE_NAMESPACE
    DEPLOY_TOOLS_IMAGE

The namespace identified by KUBE_NAMESPACE must already exist. The deployment
does not use the Helm create-namespace option.

### Container image

    IMAGE_REPOSITORY

IMAGE_REPOSITORY may be either:

    registry.example.invalid/team/wintermute
    registry.example.invalid/team/wintermute:existing-tag

When IMAGE_REPOSITORY does not include a tag, also set:

    IMAGE_TAG

### Jira chart configuration

    JIRA_URL
    JIRA_PROJECT_KEY

JIRA_URL must match the value stored in the manually managed runtime Secret.

## Resources to create in Rancher

Create the following resources in the namespace identified by KUBE_NAMESPACE.

### Registry credentials

Create a Rancher Registry Credentials Secret:

    Name: wintermute-registry-credentials
    Type: kubernetes.io/dockerconfigjson

Supply:

    Registry server
    Registry username
    Registry password

The registry server must be the hostname and optional port only. Do not include
https:// or the image repository path.

The corresponding GitLab variable is:

    WINTERMUTE_IMAGE_PULL_SECRET=wintermute-registry-credentials

### Runtime credentials

Create a regular Opaque Secret:

    Name: blackduck-wintermute-credentials
    Type: Opaque

Add these exact, case-sensitive keys:

    BLACKDUCK_URL
    BLACKDUCK_API_TOKEN
    JIRA_URL
    JIRA_USER
    JIRA_API_TOKEN

Enter raw values through the Rancher form. Rancher handles Kubernetes encoding.

The corresponding GitLab variable is:

    WINTERMUTE_RUNTIME_SECRET=blackduck-wintermute-credentials

## Optional private CA

No additional resource is required when Black Duck and Jira use publicly
trusted certificates.

If a private or corporate CA is required, create a ConfigMap in the same
namespace:

    Name: blackduck-wintermute-ca-bundle
    Key: ca.crt

The ca.crt value must contain the required PEM CA bundle.

Then configure:

    WINTERMUTE_CA_BUNDLE_CONFIGMAP=blackduck-wintermute-ca-bundle

Leave WINTERMUTE_CA_BUNDLE_CONFIGMAP empty when no private CA is required.

Registry certificate trust is separate. Kubernetes nodes and their container
runtime must already trust any private CA used by the image registry.

## Safe defaults

The included CI job defaults to:

    WINTERMUTE_IMAGE_PULL_POLICY=Always
    WINTERMUTE_IMAGE_PULL_SECRET=wintermute-registry-credentials
    WINTERMUTE_RUNTIME_SECRET=blackduck-wintermute-credentials
    WINTERMUTE_CA_BUNDLE_CONFIGMAP=

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

## Helm permissions

The deployment identity needs permission in the existing namespace to manage:

    CronJobs
    ConfigMaps
    PersistentVolumeClaims
    ServiceAccounts
    Helm release Secrets

It does not need permission to create namespaces or manage the application
credential Secrets.

## Initial deployment

Keep:

    WINTERMUTE_CRON_SUSPEND=true
    WINTERMUTE_PIPELINE_MODE=dry-run
    WINTERMUTE_CONFIRM_APPLY=false

Run the GitLab deployment job, start the CronJob manually through Rancher, and
review the Pod logs. Dry-run mode must not create Jira issues.

## First bounded apply

After accepting the dry run:

    WINTERMUTE_CRON_SUSPEND=true
    WINTERMUTE_PIPELINE_MODE=apply
    WINTERMUTE_CONFIRM_APPLY=true
    WINTERMUTE_MAX_CREATE=10

## Enable scheduling

Only after accepting the bounded apply:

    WINTERMUTE_CRON_SUSPEND=false
    WINTERMUTE_PIPELINE_MODE=apply
    WINTERMUTE_CONFIRM_APPLY=true

## Credential rotation

Rotate the registry and runtime Secrets through Rancher. The GitLab deployment
job does not create or update them.
