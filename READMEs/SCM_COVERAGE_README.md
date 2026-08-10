# SCM inventory and Black Duck coverage

Wintermute gathers read-only SCM evidence, normalizes repository identity, and reconciles the SCM estate with Black Duck registration and scan evidence.

## Boundaries

The current release is:

- GitHub-first
- Read-only
- Python standard-library only
- Provider-neutral after collection
- Independent from Jira and Datadog delivery
- Safe to run without changing repositories, properties, workflows, rulesets, or Black Duck

Onboarding execution and scan execution are not part of this release.

## GitHub inventory

Set `GITHUB_ORG` and `GITHUB_TOKEN` through an approved secret source.

Run:

    blackduck-wintermute-scm-inventory

The command gathers:

- Stable repository node identity
- Organization identity
- Repository names and canonical URLs
- Visibility and lifecycle flags
- Default branch and exact head SHA when available
- Complete GitHub language byte observations
- Custom-property definitions and repository values
- Organization rulesets and required-workflow references
- Repository Actions workflow inventories
- Provider failures and rate-limit statistics

It writes an immutable, checksum-protected SCM snapshot under:

    .wintermute/scm/inventory/snapshots/

Use a customer CA bundle where required:

    blackduck-wintermute-scm-inventory \
      --ca-bundle /path/to/customer-ca.pem

## Coverage reconciliation

Set `BLACKDUCK_URL` and `BLACKDUCK_API_TOKEN`, then run:

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

A Black Duck project or version existing does not prove a successful scan.

## Repository mapping

Mapping precedence is:

1. Provider-native repository ID in Black Duck metadata
2. Canonical repository URL in Black Duck metadata
3. Explicit reviewed mapping
4. Exact namespace and repository naming recommendation
5. Normalized project-name recommendation

Only the first three are authoritative.

Name-based matches are recommendations. Conflicting evidence is reported and never silently accepted.

Default Black Duck metadata field names are:

    scm_provider
    scm_provider_instance
    scm_repository_id
    scm_repository_url

They can be overridden with coverage command options.

## Scan evidence

Coverage reads Black Duck project-version, BOM-status, code-location, and scan-summary evidence.

A successful scan requires an explicit successful terminal status plus a completion timestamp or provider evidence identity.

If Black Duck does not expose enough evidence, scan state remains unknown. Wintermute does not convert missing evidence into never-scanned.

A validated external evidence file may be supplied with:

    --scan-evidence PATH

Use this only when the file represents a trusted source such as validated scan receipts.

## Outputs

A coverage snapshot contains:

- metadata.json
- repositories.json
- provider-evidence.json
- onboarding-controls.json
- blackduck-projects.json
- mappings.json
- coverage-report.json
- scan-gaps.json
- failures.json
- checksums.json
- READY
- COMPLETE

Snapshots are staged, promoted atomically, checksum-verified, and retained independently from vulnerability cohorts.

## Metrics

Coverage reports:

- Onboarding coverage
- Authoritative mapping coverage
- Successful scan coverage
- Fresh successful scan coverage

The denominator is eligible repositories. A zero denominator produces an unknown percentage rather than a fabricated zero.

## Safety

The GitHub and Black Duck integrations in this release issue read-only requests.

Do not add mutation endpoints to the inventory or coverage clients.

Before release:

    python -m pytest -q tests
    python scripts/validate_entrypoints.py --require-installed
    python scripts/validate_release.py --skip-docker
    zsh scripts/check_secrets.zsh
