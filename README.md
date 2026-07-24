# unofficialblackduck-harness

An unofficial integration harness for Black Duck SCA vulnerability workflows.

The harness can:

- Discover parent and child Black Duck project-version relationships.
- Collect vulnerabilities affecting child project versions.
- Retrieve CVSS scores and vectors.
- Retrieve the Black Duck E+H Entity project custom field.
- Build a CVE-centered Jira hierarchy.
- Publish CVE Epics and affected project/version Tasks to Jira.
- Preserve caches and Jira state between runs.
- Run the complete Jira workflow through one pipeline command.
- Run as a secure Kubernetes CronJob.
- Push container images to a configurable private registry.
- Optionally publish high-risk vulnerability events to Datadog.

This is not an officially supported Black Duck integration.

## Current status

The application, orchestration module, container image, Kubernetes deployment resources, persistent storage configuration, tests, and build workflows have been implemented.

The project is currently a release candidate awaiting customer-specific configuration and environment validation.

Remaining production work requires customer values such as:

- Private registry address and repository.
- Kubernetes namespace and storage class.
- Customer CA certificate chain.
- Runtime credentials.
- Jira project key.
- Jira custom-field IDs.
- Cron schedule and timezone.
- Resource requests and limits.
- Customer acceptance of dry-run output.
- Customer acceptance of a limited Jira apply.

## Requirements

Local development requires:

- Python 3.12
- virtualenv
- pip
- pytest

Container and Kubernetes development optionally requires:

- Docker
- kubectl
- Access to the private container registry
- Access to the target Kubernetes cluster

## Project layout

The application is split into Jira and Datadog packages.

    src/
    └── harness/
        ├── jira/
        │   ├── config/
        │   │   └── jira-rollup-config.json
        │   ├── find_parent_projects.py
        │   ├── subp_vuln_rollup.py
        │   ├── findings_hierarchy_plan.py
        │   ├── findings_to_jira.py
        │   └── pipeline.py
        ├── datadog/
        │   ├── policy_vuln_find.py
        │   ├── policy_vuln_pull.py
        │   └── findings_to_datadog.py
        └── paths.py

Container and Kubernetes files include:

    Dockerfile
    .dockerignore
    .github/workflows/container-build.yml
    .github/workflows/kubernetes-deploy.yml
    deploy/base/
    deploy/examples/
    deploy/overlays/customer/

Additional documentation is stored under:

    READMEs/

## Local setup

Create a virtual environment:

    python3.12 -m virtualenv .venv

Activate it:

    source .venv/bin/activate

Install the project in editable mode:

    python -m pip install -e .

Install the test dependency if required:

    python -m pip install "pytest>=8,<9"

Run tests:

    python -m pytest -q

Compile the Python package:

    python -m compileall -q src/harness

Editable installation means normal source-file changes are immediately available.

Reinstall after changing:

- pyproject.toml
- The package structure
- Installed command entry points
- Package metadata

## Installed commands

Jira commands:

    blackduck-find-parents
    blackduck-vuln-rollup
    blackduck-hierarchy-plan
    blackduck-findings-to-jira
    blackduck-jira-pipeline

Datadog commands:

    blackduck-policy-vuln-find
    blackduck-policy-vuln-pull
    blackduck-findings-to-datadog

Verify installation:

    blackduck-find-parents --help
    blackduck-vuln-rollup --help
    blackduck-hierarchy-plan --help
    blackduck-findings-to-jira --help
    blackduck-jira-pipeline --help
    blackduck-policy-vuln-find --help
    blackduck-policy-vuln-pull --help
    blackduck-findings-to-datadog --help

## Python module execution

The installed commands and Python module commands run the same source code.

Jira modules:

    python -m harness.jira.find_parent_projects
    python -m harness.jira.subp_vuln_rollup
    python -m harness.jira.findings_hierarchy_plan
    python -m harness.jira.findings_to_jira
    python -m harness.jira.pipeline

Datadog modules:

    python -m harness.datadog.policy_vuln_find
    python -m harness.datadog.policy_vuln_pull
    python -m harness.datadog.findings_to_datadog

Module execution is recommended for IntelliJ run configurations and debugging.

## Output layout

Generated files no longer default to the repository root.

Default output root:

    .harness/

Jira output:

    .harness/jira/

Datadog output:

    .harness/datadog/

Override the output root with:

    export HARNESS_OUTPUT_DIR="/custom/output/path"

The Kubernetes deployment uses:

    HARNESS_OUTPUT_DIR=/var/lib/blackduck-harness

## Black Duck authentication

Set:

    export BLACKDUCK_URL="https://blackduck.example.com"
    export BLACKDUCK_API_TOKEN="your-token"

Do not store real tokens in source files, container images, or shared IntelliJ configurations.

## Jira authentication

Jira URL:

    export JIRA_URL="https://jira.example.com"

Basic authentication:

    export JIRA_USER="user@example.com"
    export JIRA_API_TOKEN="your-api-token"

Bearer or PAT authentication:

    export JIRA_PAT="your-token"

For bearer authentication, configure:

    {
      "jira": {
        "auth_mode": "bearer"
      }
    }

If Jira URL or credentials are incomplete, the Jira publisher forces dry-run mode.

## Jira configuration

Default configuration:

    src/harness/jira/config/jira-rollup-config.json

Customer configuration must provide:

- Jira project key.
- Jira URL or JIRA_URL.
- Jira authentication mode.
- Jira issue types.
- Jira hierarchy parent mode.
- Entity custom-field ID.
- Project Name field ID.
- Project Version field ID.
- CVSS Vector field ID.
- CVSS Score field ID.
- Desired labels.
- Desired summary templates.
- Desired severity mappings.

Credentials must not be placed in the Jira JSON configuration.

## Jira workflow

The normal Jira workflow is:

    Black Duck
        |
        v
    blackduck-find-parents
        |
        v
    .harness/jira/parent_projects.csv
        |
        v
    blackduck-vuln-rollup
        |
        v
    .harness/jira/findings.csv
        |
        v
    blackduck-hierarchy-plan
        |
        v
    .harness/jira/jira-hierarchy-plan.json
        |
        v
    blackduck-findings-to-jira
        |
        v
    Jira CVE Epics and affected project/version Tasks

The complete workflow can also be executed through:

    blackduck-jira-pipeline

## Parent discovery

Run:

    blackduck-find-parents

Default outputs:

    .harness/jira/parent_projects.csv
    .harness/jira/parent_project_changes.csv
    .harness/jira/cache/parent_projects_cache.json

Parent discovery uses incremental synchronization.

It:

1. Builds a current Black Duck project-version inventory.
2. Identifies versions by stable Black Duck API URL.
3. Creates metadata fingerprints.
4. Compares current fingerprints with cached fingerprints.
5. Rescans new, changed, failed, or expired versions.
6. Compares previous and current relationship sets.
7. Writes added and removed relationship deltas.

Force a complete relationship rescan:

    blackduck-find-parents \
      --refresh-all \
      --debug

Enable BOM name and version fallback:

    blackduck-find-parents \
      --resolve-bom-names \
      --debug

Detailed documentation:

    READMEs/FIND_PARENTS_README.md

## Vulnerability rollup

Run:

    blackduck-vuln-rollup

When no input mode is supplied, it automatically reads:

    .harness/jira/parent_projects.csv

Single-parent mode remains available:

    blackduck-vuln-rollup \
      --parent-project "Parent Project" \
      --parent-version "1.0"

Default output:

    .harness/jira/findings.csv

Default API cache:

    .harness/jira/cache/subp_vuln_rollup_cache.json

The rollup collects:

- Parent project and version.
- Affected child project and version.
- Component name.
- Component display version.
- Component-version URL.
- Vulnerability ID.
- Vulnerability URL.
- Severity.
- Score.
- CVSS vector.
- E+H Entity.

Refresh the Black Duck API cache:

    blackduck-vuln-rollup \
      --refresh-api-cache \
      --debug

Require Entity:

    blackduck-vuln-rollup \
      --require-entity

Do not require Entity against a test Black Duck instance that does not define it.

## Component version handling

Component display values and Black Duck component URLs are separate fields.

Example:

    component = Thymeleaf
    component_version = 3.0.15.RELEASE
    component_version_href = https://blackduck.example/api/components/.../versions/...

Jira titles use the display version.

Task descriptions retain the component-version URL.

If an older findings file contains a URL in component_version, regenerate findings before regenerating the hierarchy plan.

## Jira hierarchy planning

Run:

    blackduck-hierarchy-plan

Default input:

    .harness/jira/findings.csv

Default outputs:

    .harness/jira/jira-hierarchy-plan.json
    .harness/jira/jira-hierarchy-summary.csv
    .harness/jira/jira-hierarchy-nodes.csv

Default hierarchy mode:

    vulnerability-project

Default hierarchy:

    Epic: one CVE or vulnerability
    └── Task: one affected Black Duck project/version

Example:

    Epic: [Black Duck] CVE-2022-22938
    └── Task: Black Duck: BLOCKER Alert - DG-WG-Demo - version 1.0 - Thymeleaf version 3.0.15.RELEASE

Focused CVE test:

    blackduck-hierarchy-plan \
      --only-vulnerability CVE-2022-22938 \
      --plan-out .harness/jira/tests/CVE-2022-22938-plan.json \
      --summary-out .harness/jira/tests/CVE-2022-22938-summary.csv \
      --nodes-out .harness/jira/tests/CVE-2022-22938-nodes.csv \
      --debug

Do not combine a focused CVE test with a small finding limit. A limit can remove component rows needed for complete aggregation.

Detailed documentation:

    READMEs/HIERARCHY_PLAN_README.md

## Jira publishing

Hierarchy publishing is the default.

Run a dry run:

    blackduck-findings-to-jira \
      --dry-run \
      --debug

Default hierarchy plan:

    .harness/jira/jira-hierarchy-plan.json

Default outputs:

    .harness/jira/jira-rollup-plan.json
    .harness/jira/jira-rollup-results.csv

The publisher fails if the default hierarchy plan does not exist.

It does not silently fall back to flat findings.

## Jira apply

Run a limited apply first:

    blackduck-findings-to-jira \
      --apply \
      --max-create 5 \
      --debug

After validation:

    blackduck-findings-to-jira \
      --apply \
      --debug

Hierarchy nodes are processed in dependency order:

    Epic
    Task
    Legacy vulnerability or Subtask

## Flat Jira mode

Flat mode creates one Jira Task per raw finding.

It is not the default.

It must be selected explicitly:

    blackduck-findings-to-jira \
      --flat-findings \
      --dry-run \
      --debug

Flat apply:

    blackduck-findings-to-jira \
      --flat-findings \
      --apply \
      --max-create 5 \
      --debug

## Jira Task titles

Default template:

    Black Duck: {alert_severity} Alert - {affected_project} - version {affected_version} - {component_summary}

Single-component example:

    Black Duck: BLOCKER Alert - DG-WG-Demo - version 1.0 - Thymeleaf version 3.0.15.RELEASE

Multiple-component example:

    Black Duck: BLOCKER Alert - DG-WG-Demo - version 1.0 - 3 affected components

Default display mapping:

    CRITICAL -> BLOCKER
    HIGH     -> HIGH
    MEDIUM   -> MEDIUM
    LOW      -> LOW
    UNKNOWN  -> UNKNOWN

BLOCKER is a configurable display value.

The original Black Duck severity remains available in findings, descriptions, statistics, and hierarchy context.

## Jira labels

Generated Jira issues include readable labels:

    BDAlert
    CVE-2022-22938
    blackduck
    subproject_rollup
    bd_sev_critical

Deterministic labels are retained for Jira lookup and deduplication.

Example:

    bd_cve_project_0123456789abcdef01234567

Titles are not used as the primary deduplication key.

## CVSS vectors

CVSS vectors use Jira no-format markup in wiki descriptions.

This prevents sequences such as:

    E:P

from becoming Jira emoticons.

Example vector:

    CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P/RL:O/RC:C

CVSS vectors and scores can also be mapped to Jira custom fields.

## E+H Entity

The vulnerability rollup attempts to retrieve:

    E+H Entity

Data flow:

    Black Duck project custom field
        |
        v
    findings.csv entity column
        |
        v
    hierarchy Task context
        |
        v
    Jira Entity custom field

Entity is not shown in the Task description by default.

Configure the Jira Entity field ID under:

    hierarchy.field_mappings.entity.field_id

Jira screen tabs and field placement are Jira administration configuration.

The integration can populate the Entity field, but it cannot create the Jira Default or Entity tabs.

## Jira local state

Default state file:

    .harness/jira/state/jira-rollup-state.json

The state records:

- Hierarchy external IDs.
- Jira issue keys.
- Lookup labels.
- Node types.
- Last known Jira status.
- Link state.
- First and last seen times.
- Last actions.

Local state is checked before Jira.

Deleting Jira issues manually does not update local state.

A stale local state match produces:

    skip_existing_state

Reconcile local state against Jira:

    blackduck-findings-to-jira \
      --refresh-existing \
      --dry-run \
      --debug

Use an isolated state path for testing:

    --state .harness/jira/tests/new-test-state.json

## Managed field synchronization

Preview updates to configured Jira fields:

    blackduck-findings-to-jira \
      --refresh-existing \
      --sync-existing-fields \
      --dry-run \
      --debug

Apply updates:

    blackduck-findings-to-jira \
      --refresh-existing \
      --sync-existing-fields \
      --apply \
      --max-create 5 \
      --debug

## Complete Jira pipeline

Run every Jira stage through one command:

    blackduck-jira-pipeline --dry-run

Equivalent module command:

    python -m harness.jira.pipeline --dry-run

Pipeline stages:

1. Parent relationship discovery.
2. Vulnerability rollup.
3. Hierarchy planning.
4. Jira publishing.

Apply must be explicit:

    blackduck-jira-pipeline --apply

Limited apply:

    blackduck-jira-pipeline \
      --apply \
      --max-create 5

## Strict pipeline mode

Strict mode is the default.

If relationship or vulnerability collection failures occur:

- Jira publishing is skipped.
- Diagnostics remain available.
- The pipeline exits nonzero.
- Previous active output remains available.

Explicit strict mode:

    blackduck-jira-pipeline --strict

Allow partial processing only when intentionally required:

    blackduck-jira-pipeline --allow-partial

## Pipeline output and locking

Each pipeline run creates:

    .harness/jira/runs/RUN_ID/

Active summary:

    .harness/jira/pipeline-run-summary.json

Lock file:

    .harness/jira/pipeline.lock

The lock prevents overlapping direct executions.

Kubernetes concurrency protection remains the primary production safeguard.

## Container image

Build locally:

    docker build \
      --tag blackduck-harness:local \
      --file Dockerfile \
      .

Display pipeline help:

    docker run \
      --rm \
      blackduck-harness:local \
      --help

The image:

- Uses Python 3.12.10.
- Uses a multi-stage build.
- Runs as user and group 10001.
- Supports a read-only root filesystem.
- Uses blackduck-jira-pipeline as its entry point.
- Defaults to dry-run mode.
- Does not contain credentials.
- Does not contain customer certificates.
- Does not contain local findings, cache, or state.

## Kubernetes deployment

The application runs as a finite Kubernetes CronJob.

Each execution:

1. Creates a Job and Pod.
2. Mounts persistent storage.
3. Mounts Jira configuration.
4. Mounts the customer CA bundle.
5. Loads credentials from Kubernetes secrets.
6. Runs blackduck-jira-pipeline once.
7. Writes cache, state, plans, results, and diagnostics.
8. Exits.
9. Leaves persistent data for the next run.

The application is not a permanent HTTP service.

## Persistent storage

The deployment uses a PersistentVolumeClaim:

    blackduck-harness-data

Default capacity:

    5Gi

Default access mode:

    ReadWriteOnce

Mount path:

    /var/lib/blackduck-harness

The container sets:

    HARNESS_OUTPUT_DIR=/var/lib/blackduck-harness

The PVC preserves cache and Jira state across:

- Pod completion.
- Job deletion.
- CronJob updates.
- Container image updates.
- Normal deployment changes.

Deleting the PVC may delete the data depending on the storage class reclaim policy.

Do not delete the PVC during normal upgrades.

## Kubernetes concurrency and security

The CronJob uses:

    concurrencyPolicy: Forbid

Container security settings include:

    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    seccompProfile: RuntimeDefault

All Linux capabilities are dropped.

Writable locations are limited to:

    /var/lib/blackduck-harness
    /tmp

## Kubernetes resources

Base:

    deploy/base/

Customer overlay:

    deploy/overlays/customer/

Examples:

    deploy/examples/

The CronJob is initially configured with:

    suspend: true
    --dry-run
    --strict

Do not enable the schedule or apply mode before customer acceptance.

## Private registry

The container registry is configurable.

GitHub variables:

    REGISTRY_HOST
    REGISTRY_REPOSITORY

GitHub secrets:

    REGISTRY_USERNAME
    REGISTRY_PASSWORD

Resulting image:

    REGISTRY_HOST/REGISTRY_REPOSITORY:COMMIT_SHA

Production should use an immutable commit SHA or image digest.

## Container build workflow

Workflow:

    .github/workflows/container-build.yml

It:

1. Installs Python.
2. Installs the package.
3. Compiles the package.
4. Runs tests.
5. Builds the image.
6. Logs in to the private registry.
7. Pushes the immutable image.
8. Reports the image digest.

## Kubernetes deployment workflow

Workflow:

    .github/workflows/kubernetes-deploy.yml

The workflow is manually triggered.

Supported operations:

| Operation | Behavior |
|---|---|
| render | Render and upload manifests |
| diff | Compare rendered manifests with the cluster |
| apply | Apply manifests to the cluster |

Supported pipeline modes:

| Mode | Behavior |
|---|---|
| dry-run | Generate Jira plans without modifying Jira |
| apply | Permit Jira issue creation and updates |

GitHub environment variables:

    REGISTRY_HOST
    REGISTRY_REPOSITORY
    KUBE_NAMESPACE
    CRON_SCHEDULE
    CRON_TIMEZONE

GitHub environment secret:

    KUBE_CONFIG_B64

KUBE_CONFIG_B64 contains the base64-encoded kubeconfig used by the manual deployment workflow for diff and apply operations.

Applying active Jira mode requires explicit confirmation in the deployment workflow.

## Registry pull secret

Expected Kubernetes secret:

    blackduck-harness-registry

It contains private-registry pull credentials.

Registry credentials must not be committed.

## Runtime credential secret

Expected Kubernetes secret:

    blackduck-harness-credentials

It can supply:

    BLACKDUCK_URL
    BLACKDUCK_API_TOKEN
    JIRA_URL
    JIRA_USER
    JIRA_API_TOKEN
    JIRA_PAT

Only supply the Jira credentials required for the selected authentication mode.

External Secrets, Vault, or a cloud secret manager are preferred when available.

## Customer TLS certificate

Production must not use insecure TLS.

The customer should provide the issuing root and intermediate CA chain.

Expected ConfigMap:

    blackduck-harness-ca

Expected file:

    /etc/blackduck-harness/ca/customer-ca.pem

Pipeline argument:

    --ca-bundle /etc/blackduck-harness/ca/customer-ca.pem

Environment variable:

    SSL_CERT_FILE=/etc/blackduck-harness/ca/customer-ca.pem

Do not use a short-lived leaf certificate as the trust bundle.

## Schedule and manual triggering

Base schedule:

    0 2 * * *

Base timezone:

    Etc/UTC

The CronJob initially remains suspended.

Create a manual Job:

    run_id=$(date -u +%Y%m%d%H%M%S)

    kubectl create job \
      --namespace blackduck-harness \
      --from=cronjob/blackduck-jira-pipeline \
      blackduck-jira-manual-${run_id}

Follow logs:

    kubectl logs \
      --namespace blackduck-harness \
      job/blackduck-jira-manual-RUN_ID \
      --follow

The first customer execution should be dry-run only.

## Customer information still required

### Private registry

- Registry hostname.
- Repository path.
- Authentication method.
- Registry username and password or token.
- Kubernetes image-pull secret name.
- Image tag or digest convention.

### Kubernetes

- Namespace.
- Storage class.
- PVC capacity.
- Storage reclaim policy.
- Snapshot or backup policy.
- Cron schedule.
- Cron timezone.
- CPU requests and limits.
- Memory requests and limits.
- Maximum runtime.
- Kustomize acceptance or Helm requirement.

### TLS

- Root and intermediate CA bundle.
- Confirmation that the CA validates Black Duck.
- Confirmation that the CA validates Jira.
- ConfigMap or Secret preference.

### Runtime secrets

- Black Duck URL.
- Black Duck API token.
- Jira URL.
- Jira authentication mode.
- Jira username and API token or PAT.
- Secret-management platform.

### Jira

- Jira project key.
- Entity field ID and type.
- Project Name field ID.
- Project Version field ID.
- CVSS Vector field ID.
- CVSS Score field ID.
- Confirmation of Epic and Task parent behavior.
- Default and Entity screen-tab configuration.

### Operations

- Dry-run or apply schedule.
- Strict or partial failure policy.
- Existing-field synchronization policy.
- Deleted-issue recreation policy.
- Run-output retention period.
- Whether Datadog also requires a CronJob.

## Customer deployment sequence

1. Receive registry information.
2. Receive Kubernetes configuration.
3. Receive the customer CA bundle.
4. Receive Jira custom-field IDs.
5. Configure the customer overlay.
6. Build and push an immutable image.
7. Render the Kubernetes resources.
8. Review the rendered manifests.
9. Create secrets and the CA ConfigMap.
10. Deploy with the CronJob suspended.
11. Trigger a manual dry-run Job.
12. Inspect logs and PVC output.
13. Trigger a second dry-run Job.
14. Confirm cache and Jira state reuse.
15. Run a limited Jira apply with max-create 5.
16. Verify Jira Epic and Task behavior.
17. Enable the schedule after acceptance.

## Optional Datadog workflow

The Datadog workflow remains separate.

Stages:

    blackduck-policy-vuln-find
        |
        v
    blackduck-policy-vuln-pull
        |
        v
    blackduck-findings-to-datadog

Default output:

    .harness/datadog/

The current Kubernetes CronJob implementation targets Jira.

A separate Datadog CronJob can be added if required.

## Documentation

Parent discovery:

    READMEs/FIND_PARENTS_README.md

Hierarchy planning:

    READMEs/HIERARCHY_PLAN_README.md

Jira publishing:

    READMEs/FIND_2JIRA_README.md

Kubernetes deployment:

    READMEs/KUBERNETES_DEPLOYMENT_README.md

Datadog:

    READMEs/FINDINGS_TO_DATADOG_README.md
    READMEs/POLICY_VULN_FIND_README.md
    READMEs/POLICY_VULN_PULL_README.md

## License and support

Use at your own risk.

This is not an officially supported Black Duck integration.
