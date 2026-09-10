# AI-assisted central scanning

Wintermute inventories repositories, analyzes build evidence using Azure OpenAI
or an OpenAI-compatible vLLM endpoint, and converts validated profiles into
deterministic scan contracts.

A central GitLab project runs those contracts against exact repository commits.
Target repositories do not need individual CI files or merge requests.

TODO: This is the foundation of fleet and remote k8s detect scanning broker for BDSCA,
that'll take 6months of work (sounds easy, but it isnt for something worth using imho).


## Architecture

```text
GitHub / GitLab inventory
          |
Immutable SCM snapshots
          |
Sanitized evidence → Azure OpenAI / vLLM
          |
Validated scan profiles
          |
Contract consolidation and review
          |
Central registry + managed GitLab launcher
          |
Pinned scan image → Black Duck Bridge
          |
Persistent execution receipts
```

The Python runtime uses the standard library only. AI recommends configuration;
it does not supply executable shell commands or pipeline YAML.

## Repository inventory

GitHub and GitLab inventory share provider-neutral identities and snapshot formats.
GitLab group discovery uses schema-aware GraphQL with REST fallback.

Inventory one GitLab repository without listing its namespace:

```bash
python -m wintermute.scm \
  --scm-url https://gitlab.example.com \
  --project team/application
```

Set `GITLAB_TOKEN` for authenticated access. Snapshots include project identity,
default-branch commit, language evidence, and CI observations.

## AI providers

For vLLM, configure:

- `WINTERMUTE_AI_PROVIDER=vllm`
- `VLLM_BASE_URL`
- `VLLM_MODEL`
- `VLLM_API_KEY`, when required

For Azure OpenAI, configure:

- `WINTERMUTE_AI_PROVIDER=azure`
- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_DEPLOYMENT`
- `AZURE_OPENAI_API_KEY`

External source transmission requires `WINTERMUTE_AI_ALLOW_SOURCE=true` and
`WINTERMUTE_AI_ANONYMIZATION_KEY`.

Generate a repository profile from an inventory snapshot:

```bash
python -m wintermute.ai scm-batch-scan-profile \
  --scm-snapshot /path/to/snapshot \
  --scm-provider gitlab \
  --repository team/application \
  --max-repositories 1
```

The batch flow retrieves selected evidence lazily, sanitizes it, validates model
responses, and records immutable analysis artifacts. SQLite stores response
caching and usage accounting; compatible completed profiles can be reused.

## Contracts and central setup

Consolidation groups profiles into allowlisted scanner contracts. Assignments
requiring review remain excluded from the runtime registry until approved.
Verified template plans can be merged without manually editing the registry.

The onboarding configuration selects the verified plan, target projects, central
project, and scan image. Start with:

`src/wintermute/scm/onboarding/config/wintermute-onboard.example.json`

Select private configuration using `--config`, `WINTERMUTE_ONBOARD_CONFIG`, or
the ignored module-local `wintermute-onboard.local.json`.

```bash
python -m wintermute.scm.onboarding --config /path/to/onboarding.json --dry-run
```

Initialize-only bootstrap creates the central project. Setup then manages
explicit upgrades, protected CI variables, and project access. Apply is bound
to the reviewed plan and write budget; modified customer-managed files cause
a conflict rather than an implicit overwrite.

`GITLAB_TOKEN` supports the single-token setup workflow.
`GITLAB_ACTION_TOKEN` optionally supplies a separate mutation credential.
Setup automatically provisions the launcher's protected, masked API credential.

## Scan image and launcher

The Docker `scan` target packages Wintermute and the Bridge CLI Bundle for
AMD64 and ARM64. Bundle downloads and Bridge executables are checksum-verified;
central pipelines reference an immutable image digest.

The launcher accepts an approved project ID and full commit SHA. It verifies the
registry, reads project and commit metadata, downloads the source archive, rejects
unsafe archive entries, and uses an ephemeral workspace. GitLab credentials are
excluded from the scanner subprocess.

GitLab retains scanner and launcher receipts as job artifacts. Source cleanup
does not remove those receipts.

Dry-run performs no scanner execution. Real execution is currently gated pending
verified Bridge SCA parameter mapping; Coverity and Polaris are not completed
execution integrations.

## Code organization

- `wintermute.ai`: providers, evidence retrieval, profiles, cache, and accounting.
- `wintermute.scm`: inventory, evidence, and immutable snapshots.
- `wintermute.scm.onboarding`: contracts, review, registry bundles, and GitLab setup.
- `wintermute.scan`: registry validation, source retrieval, Bridge runtime, and receipts.

Jira and Datadog delivery remain independent of central scanning.
