# unofficialblackduck-harness

This repository contains an unofficial enhancement to Black Duck parent/child project finding alert workflows. It supplements how child findings are created in Jira so they can be linked correctly with their parent project.

# setup

## Requirements

- Python 3.12+
- `virtualenv`
- `pip`

This project currently uses only Python standard library runtime dependencies, so there is no required `requirements.txt`.

## Create a local virtual environment

macOS/Linux:

```bash
python3.12 -m virtualenv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -3.12 -m virtualenv .venv
.\.venv\Scripts\Activate.ps1
```

## Install the project

From the repository root:

```bash
python -m pip install -e .
```

This installs the project in editable mode and makes the command-line tools available.

## Verify install

```bash
blackduck-find-parents --help
blackduck-vuln-rollup --help
blackduck-hierarchy-plan --help
blackduck-findings-to-jira --help
```

## Black Duck authentication

Set Black Duck connection details as environment variables:

macOS/Linux:

```bash
export BLACKDUCK_URL="https://blackduck.example.com"
export BLACKDUCK_API_TOKEN="..."
```

Windows PowerShell:

```powershell
$env:BLACKDUCK_URL = "https://blackduck.example.com"
$env:BLACKDUCK_API_TOKEN = "..."
```

## Typical workflow

### 1. Generate rollup findings

```bash
blackduck-vuln-rollup \
  --parents-csv parent_projects.csv \
  --threshold 7 \
  --out findings.csv \
  --timeout 30 \
  --retries 1 \
  --page-limit 500 \
  --failures-out failed-rollup-relationships.csv
```

Use `--insecure` only if needed for lab/on-prem TLS testing.

### 2. Generate a Jira hierarchy plan

```bash
blackduck-hierarchy-plan \
  --findings findings.csv \
  --plan-out jira-hierarchy-plan.json \
  --summary-out jira-hierarchy-summary.csv \
  --nodes-out jira-hierarchy-nodes.csv
```

### 3. Configure Jira

Edit:

```text
src/unofficialblackduck-harness/config/jira-rollup-config.json
```

Set at least the Jira URL/project details required for your environment.

Then set Jira credentials.

Basic auth:

```bash
export JIRA_USER="user@example.com"
export JIRA_API_TOKEN="..."
```

Bearer/PAT auth:

```bash
export JIRA_PAT="..."
```

Windows PowerShell example:

```powershell
$env:JIRA_USER = "user@example.com"
$env:JIRA_API_TOKEN = "..."
```

## Jira dry run

Dry run is the default unless `--apply` is provided.

```bash
blackduck-findings-to-jira \
  --hierarchy-plan jira-hierarchy-plan.json \
  --config src/unofficialblackduck-harness/config/jira-rollup-config.json \
  --state jira-rollup-state.json \
  --results-out jira-hierarchy-publish-results.csv \
  --plan-out jira-hierarchy-publish-plan.json
```

## Jira apply run

This creates Jira issues/links.

```bash
blackduck-findings-to-jira \
  --hierarchy-plan jira-hierarchy-plan.json \
  --config src/unofficialblackduck-harness/config/jira-rollup-config.json \
  --state jira-rollup-state.json \
  --results-out jira-hierarchy-publish-results.csv \
  --plan-out jira-hierarchy-publish-plan.json \
  --apply
```

# License

Use at your own risk, this is not an officially supported pathway.