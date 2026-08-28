# SCM inventory and Black Duck coverage

Wintermute gathers read-only GitHub and GitLab evidence, normalizes repository identity, and reconciles repositories with Black Duck registration and scan evidence.

## Boundaries

The SCM workflow is:

- Read-only
- Python standard-library only
- Provider-neutral after collection
- Independent from Jira and Datadog delivery
- Safe to run without changing repositories, workflows, controls or Black Duck

## Provider selection

The provider is selected from SCM_URL or provider-specific configuration.

### GitHub

Required:

    GITHUB_ORG
    GITHUB_TOKEN

Optional:

    GITHUB_GRAPHQL_URL
    GITHUB_REST_URL

Run:

    blackduck-wintermute-scm-inventory

### GitLab

Required:

    SCM_URL=https://gitlab.example.com
    GITLAB_GROUP=group/subgroup
    GITLAB_TOKEN

Optional:

    GITLAB_REST_URL=https://gitlab.example.com/api/v4

Run:

    blackduck-wintermute-scm-inventory

Nested GitLab subgroups are included.

## GitHub evidence

GitHub collection includes:

- Stable repository and organization identity
- Visibility and lifecycle state
- Default branch and head SHA
- Language byte observations
- Custom-property definitions and assignments
- Organization rulesets
- Required-workflow references
- Actions workflow inventory

## GitLab evidence

GitLab collection includes:

- Stable project and group identity
- Nested subgroup projects
- Visibility, archived and fork state
- Default branch
- Language percentages
- GitLab CI configuration
- Local CI includes with bounded traversal
- Recent pipeline summaries
- Default-branch protection

GitLab uses schema-aware GraphQL bulk discovery. REST is used for repository files, protected branches, and fields unavailable in the installed GraphQL schema.

Pipeline access denials are cached to avoid repeatedly requesting unavailable evidence.

## Multiple providers

Customers using GitHub and GitLab can run both sequentially:

    python scripts/run_scm_multi_provider.py \
      --insecure \
      --collect-direct-scan-evidence \
      --pipeline-limit 3 \
      --max-projects 2 \
      --max-versions 5

The providers receive separate immutable snapshots:

    RUN_ID-github
    RUN_ID-gitlab

They run sequentially and do not query Black Duck concurrently.

## Inventory output

SCM inventory writes immutable, checksum-protected snapshots under:

    .wintermute/scm/inventory/snapshots/

Each snapshot contains repository inventory, evidence, controls, failures, metadata and checksums.

## Coverage reconciliation

Set:

    BLACKDUCK_URL
    BLACKDUCK_API_TOKEN

Run:

    blackduck-wintermute-coverage \
      --scm-snapshot PATH_TO_SCM_SNAPSHOT

Coverage keeps these states separate:

1. Repository exists
2. Repository is eligible
3. Repository is onboarded
4. Repository is authoritatively mapped
5. Black Duck project and versions exist
6. Explicit successful scan evidence exists
7. The latest successful scan is within the freshness SLA

A Black Duck project existing does not prove that it was scanned.

## Repository mapping

Mapping precedence is:

1. Provider-native repository ID in Black Duck metadata
2. Canonical repository URL in Black Duck metadata
3. Explicit reviewed mapping
4. Exact namespace and repository naming recommendation
5. Normalized project-name recommendation

Only the first three are authoritative.

Default Black Duck metadata fields are:

    scm_provider
    scm_provider_instance
    scm_repository_id
    scm_repository_url

## Coverage output

A coverage snapshot contains:

- Repository inventory
- Provider evidence
- Onboarding controls
- Black Duck projects
- Mapping decisions
- Coverage report
- Scan gaps
- Failures
- Checksums
- READY and COMPLETE markers

Coverage snapshots are independent from vulnerability cohorts.

## TLS

Certificate verification is enabled by default.

Use a customer CA bundle:

    blackduck-wintermute-scm-inventory \
      --ca-bundle /path/to/customer-ca.pem

Use insecure mode only for controlled testing.

## Validation

Run:

    python -m pytest -q tests
    python scripts/validate_entrypoints.py
    python scripts/validate_release.py --skip-docker

Live dual-provider validation:

    python scripts/run_scm_multi_provider.py \
      --insecure \
      --collect-direct-scan-evidence

SCM clients must remain read-only.
