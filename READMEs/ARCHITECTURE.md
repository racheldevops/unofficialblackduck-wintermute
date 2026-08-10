# Wintermute architecture

Wintermute separates Black Duck collection from destination delivery.

    Black Duck
        |
        v
    Shared inventory, lineage, collection and normalization
        |
        v
    Immutable cohort
        |
        +--> Jira
        |
        +--> Datadog
        |
        +--> Future destinations

## Shared source layer

The wintermute.blackduck package owns:

- Authentication and bearer-token refresh
- TLS, retry and pagination behavior
- API and discovery caches
- Project and project-version inventory
- Parent and child lineage discovery
- Candidate discovery
- Vulnerable component and vulnerability collection
- Score, exploitability, reachability and policy enrichment
- Normalized finding identities
- Collection manifests, checksums and cohorts

Destination packages must not implement independent Black Duck clients or vulnerability parsers.

## Collection scopes

| Scope | Purpose |
|---|---|
| parent-rollup | Discover or consume parent relationships, then collect each unique child version once |
| candidate-projects | Collect project versions selected by candidate discovery |
| all-project-versions | Collect every project version matching optional inventory filters |
| explicit-project-versions | Collect only project versions supplied in an input file |

The cohort source defaults to parent-rollup because product lineage is the primary customer requirement.

## Identity model

A direct finding is identified by:

- Black Duck project-version identity
- Component-version identity
- Vulnerability identity

Parent lineage does not change that direct identity. A child version shared by several products is collected once, then projected into each parent context for Jira.

## Destination profiles

Jira normally selects findings with score greater than or equal to 7 and retains parent lineage.

Datadog normally selects findings with score greater than 8.9 and requires exploit availability.

A cohort can contain a broader source set so each destination can apply its own criteria without reloading Black Duck.

## State boundaries

Shared Black Duck state contains source caches and immutable cohorts.

Jira state contains Jira issue keys, hierarchy identities, links and synchronization state.

Datadog state contains active event groups, event identifiers and resolution state.

Destination state is never shared between publishers.

## Compatibility

Existing blackduck-find-parents, blackduck-vuln-rollup, Jira and Datadog commands remain supported as compatibility interfaces over the shared source layer.

The general source command is:

    blackduck-wintermute-pull --help

The production cohort commands are:

    blackduck-wintermute-cohort-source
    blackduck-wintermute-jira-cohort
    blackduck-wintermute-datadog-cohort

## SCM intelligence and coverage

SCM inventory is an independent read-only source workflow:

    GitHub and future SCM providers
        |
        v
    Provider-specific collection
        |
        v
    Normalized repository and evidence models
        |
        v
    Immutable SCM inventory snapshot
        |
        v
    Black Duck mapping and coverage reconciliation

Stable repository identity uses provider, provider instance and provider-native immutable repository ID. Repository names and URLs remain descriptive attributes and may change without changing identity.

Provider response shapes do not enter coverage logic.

Coverage keeps onboarding, authoritative mapping, Black Duck registration, successful scan evidence and freshness as separate states.

Name-based Black Duck mappings are recommendations. They are never silently accepted.

SCM coverage snapshots are independent from vulnerability cohorts. GitHub or SCM evidence failure must not block Jira or Datadog vulnerability delivery.

The current SCM release is read-only. Future onboarding execution and Harvester scanning remain separate controlled workflows.
