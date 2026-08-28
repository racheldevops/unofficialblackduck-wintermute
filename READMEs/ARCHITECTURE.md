# Wintermute architecture

Wintermute separates source collection, destination delivery, SCM coverage, and controlled Black Duck actions.

    Black Duck
        |
        v
    Shared inventory, lineage and normalized findings
        |
        v
    Immutable cohort
        |
        +--> Jira
        |
        +--> Datadog

    GitHub / GitLab
        |
        v
    Immutable SCM inventory
        |
        v
    Black Duck coverage reconciliation

    Black Duck + GitLab CIP evidence
        |
        v
    Checksum-protected action plan
        |
        v
    Dry-run or confirmed Black Duck action execution

## Shared Black Duck layer

The wintermute.blackduck package owns:

- Authentication and bearer-token refresh
- TLS, retry, request pacing and circuit breaking
- API and discovery caches
- Project and project-version inventory
- Parent and child lineage discovery
- Vulnerable component and vulnerability collection
- Normalized finding identities
- Collection manifests, checksums and cohorts

Destination packages must not implement independent Black Duck clients or vulnerability parsers.

## Collection scopes

| Scope | Purpose |
|---|---|
| parent-rollup | Discover or consume parent relationships, then collect each unique child version once |
| candidate-projects | Collect project versions selected by candidate discovery |
| all-project-versions | Collect project versions matching inventory filters |
| explicit-project-versions | Collect project versions supplied in an input file |

## Identity model

A direct finding is identified by:

- Black Duck project-version identity
- Component-version identity
- Vulnerability identity

Parent lineage does not change direct finding identity. Shared child versions are collected once and projected into each parent context.

SCM repository identity uses:

- Provider
- Provider instance
- Provider-native immutable repository ID

Names and URLs are descriptive and may change without changing identity.

## State boundaries

| State | Contents |
|---|---|
| Black Duck source | Collection caches and immutable cohorts |
| Jira | Issue keys, hierarchy identities and link state |
| Datadog | Event groups, event identities and resolution state |
| SCM | Repository, evidence, control and coverage snapshots |
| Black Duck actions | Plans, checksums, execution receipts and CIP caches |

Destination state is not shared between publishers.

## SCM providers

GitHub uses GraphQL for repository inventory and REST for provider evidence.

GitLab uses schema-aware GraphQL bulk discovery with REST fallback for repository files, protected branches and unsupported fields. Nested GitLab subgroups are included.

GitHub and GitLab can run sequentially in one validation operation. Each provider receives its own immutable inventory and coverage snapshot.

Coverage keeps onboarding, authoritative mapping, registration, successful scan evidence and scan freshness as separate states.

Name-based mappings are recommendations and are never silently accepted.

## Black Duck actions

Actions are separate from normal collection.

An action plan contains:

- Target Black Duck instance
- Observed state and fingerprint
- Desired state
- Evidence
- Ownership marker
- Read, write and action limits
- Expiration

The executor validates checksums, rereads state, rejects stale plans, preserves human decisions, applies allowlisted action kinds, and verifies writes with a final read.

Apply mode requires explicit confirmation. Dry-run performs no writes.

## CIP remediation

The CIP workflow:

1. Finds a vulnerable Linux component occurrence.
2. Resolves BDSA identifiers to CVEs.
3. Reads CIP security records from GitLab.
4. Resolves the configured CIP tag.
5. Verifies fix-commit containment.
6. Creates actions only for conclusively fixed CVEs.
7. Updates the project-scoped Black Duck remediation resource.

Planning uses a read token. Apply can use a separate write-capable token.

## Compatibility

Existing standalone Jira, Datadog, parent discovery and candidate commands remain supported.

The general Black Duck source command is:

    blackduck-wintermute-pull --help

The production cohort commands are:

    blackduck-wintermute-cohort-source
    blackduck-wintermute-jira-cohort
    blackduck-wintermute-datadog-cohort

The current SCM workflows are read-only. Repository mutation and scan execution remain separate future workflows.
