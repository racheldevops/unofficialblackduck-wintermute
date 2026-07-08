# unofficialblackduck-harness

NOTE: THIS IS IN ACTIVE DEV AND WILL HAVE SOME CHANGES THAT ARE WIP

This repository contains an unofficial enhancement to Black Duck SCA parent/child project finding alert workflows. It can roll up vulnerabilities from affected Black Duck project versions, plan Jira remediation hierarchies, publish those hierarchies to Jira, and optionally send high-risk vulnerability events to Datadog.

## setup

### Requirements

- Python 3.12+
- `virtualenv`
- `pip`

This project currently uses only Python standard library runtime dependencies, so there is no required `requirements.txt`.

### Create a local virtual environment

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

### Install the project

From the repository root:

```bash
python -m pip install -e .
```

This installs the project in editable mode and makes the command-line tools available.

### Verify install

```bash
blackduck-find-parents --help
blackduck-vuln-rollup --help
blackduck-hierarchy-plan --help
blackduck-findings-to-jira --help
blackduck-policy-vuln-find --help
blackduck-policy-vuln-pull --help
blackduck-findings-to-datadog --help
```

## Black Duck authentication

Set Black Duck connection details as environment variables:

```bash
export BLACKDUCK_URL="https://blackduck.example.com"
export BLACKDUCK_API_TOKEN="..."
```

Windows PowerShell:

```powershell
$env:BLACKDUCK_URL = "https://blackduck.example.com"
$env:BLACKDUCK_API_TOKEN = "..."
```

## Jira remediation workflow

### Default Jira hierarchy

The default Jira hierarchy is now CVE/vulnerability remediation-forward:

```text
Epic: CVE / vulnerability
└── Task: CVE + affected Black Duck project/version
```

Example:

```text
[Black Duck] CVE-2018-1000620
└── CVE-2018-1000620 Project juicy_cam.juiced 1.0.0
```

The affected project/version comes from the directly affected Black Duck project version in `findings.csv`:

```text
affected_project = subproject
affected_version = subproject_version
affected_project_version_href = subproject_version_href
```

Parent project/version remains in node metadata and descriptions for traceability, but it does not drive the default Jira hierarchy.

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

### 2. Generate the default CVE/project-version Jira hierarchy plan

`--hierarchy-mode vulnerability-project` is the default, but it is shown explicitly here for clarity.

```bash
blackduck-hierarchy-plan \
  --findings findings.csv \
  --hierarchy-mode vulnerability-project \
  --plan-out jira-hierarchy-plan.json \
  --summary-out jira-hierarchy-summary.csv \
  --nodes-out jira-hierarchy-nodes.csv
```

A focused test plan can filter before nodes are built:

```bash
blackduck-hierarchy-plan \
  --findings findings.csv \
  --hierarchy-mode vulnerability-project \
  --plan-out jira-hierarchy-plan.json \
  --summary-out jira-hierarchy-summary.csv \
  --nodes-out jira-hierarchy-nodes.csv \
  --only-parent-project "cc-goat" \
  --only-parent-version "v2" \
  --only-subproject "juicy_cam.juiced" \
  --only-vulnerability "CVE-2018-1000620"
```

Expected default output shape:

```text
CVE Epic nodes:          number of unique CVEs/vulnerabilities
Project-version Tasks:   number of CVE + affected project/version pairs
Vulnerability nodes:     0
```

### Legacy Jira hierarchy mode

The old project-centered hierarchy is still available:

```text
Epic: parent project/version
└── Story: child/subproject version
    └── Vulnerability issue/subtask
```

Use:

```bash
blackduck-hierarchy-plan \
  --findings findings.csv \
  --hierarchy-mode project-subproject-vulnerability \
  --plan-out jira-hierarchy-plan-legacy.json \
  --summary-out jira-hierarchy-summary-legacy.csv \
  --nodes-out jira-hierarchy-nodes-legacy.csv
```

### 3. Configure Jira

Edit:

```text
src/unofficialblackduck-harness/config/jira-rollup-config.json
```

Set at least the Jira URL/project details required for your environment.

The default hierarchy config is intended for Epic -> Task creation with Jira parent relationships:

```json
{
  "hierarchy": {
    "epic_issue_type": "Epic",
    "story_issue_type": "Task",
    "vulnerability_issue_type": "Subtask",
    "story_parent_mode": "jira_parent",
    "vulnerability_parent_mode": "jira_parent",
    "issue_link_type": "Relates",
    "epic_link_field": ""
  }
}
```

If your Jira instance does not allow Task issues directly under Epics with `parent`, set:

```json
{
  "hierarchy": {
    "story_parent_mode": "issue_link",
    "issue_link_type": "Relates"
  }
}
```

or:

```json
{
  "hierarchy": {
    "story_parent_mode": "epic_link_field",
    "epic_link_field": "customfield_XXXXX"
  }
}
```

### 4. Set Jira credentials

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

### 5. Jira hierarchy dry run

Dry run is the default unless `--apply` is provided.

Apply targeting filters at plan time when possible. The Jira dry run should normally consume the already-filtered hierarchy plan:

```bash
blackduck-findings-to-jira \
  --hierarchy-plan jira-hierarchy-plan.json \
  --config src/unofficialblackduck-harness/config/jira-rollup-config.json \
  --state jira-hierarchy-publish-test-state.json \
  --results-out jira-hierarchy-publish-test-results.csv \
  --plan-out jira-hierarchy-publish-test-plan.json \
  --dry-run \
  --debug
```

Expected dry-run payload examples in the results/plan output:

```text
Epic: [Black Duck] CVE-2018-1000620
Task: CVE-2018-1000620 Project juicy_cam.juiced 1.0.0
```

When `story_parent_mode` is `jira_parent`, the Task dry-run payload should include a Jira parent key.

### 6. Jira apply run

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

## Flat Jira findings mode

Flat Jira publishing remains available and unchanged. It creates one Jira issue per unique rollup finding from `findings.csv`.

Dry run:

```bash
blackduck-findings-to-jira \
  --findings findings.csv \
  --config src/unofficialblackduck-harness/config/jira-rollup-config.json \
  --state jira-rollup-state.json \
  --results-out jira-rollup-results.csv \
  --plan-out jira-rollup-plan.json
```

Apply:

```bash
blackduck-findings-to-jira \
  --findings findings.csv \
  --config src/unofficialblackduck-harness/config/jira-rollup-config.json \
  --state jira-rollup-state.json \
  --results-out jira-rollup-results.csv \
  --plan-out jira-rollup-plan.json \
  --apply
```

## Optional Datadog Events workflow

This workflow is separate from the Jira workflow. It is split into three stages so the cheap discovery step can run frequently and only trigger the intensive pull/send path when candidates change.

Workflow:

```text
blackduck-policy-vuln-find
  -> policy_candidate_projects.csv and policy_candidate_trigger.json
  -> blackduck-policy-vuln-pull
  -> policy_findings.csv
  -> blackduck-findings-to-datadog
  -> Datadog Events
```

### Datadog and Black Duck auth

```bash
export BLACKDUCK_URL="https://blackduck.example.com"
export BLACKDUCK_API_TOKEN="..."
export DATADOG_API_KEY="..."
```

### 1. Fast candidate find

```bash
blackduck-policy-vuln-find \
  --out policy_candidate_projects.csv \
  --changes-out policy_candidate_changes.csv \
  --trigger-out policy_candidate_trigger.json \
  --cache policy_vuln_find_cache.json \
  --refresh-older-than-hours 6
```

Automation should inspect `policy_candidate_trigger.json`. If `should_trigger_pull` is true, run the pull and Datadog publish stages.

### 2. Intensive vulnerability pull

```bash
blackduck-policy-vuln-pull \
  --candidates policy_candidate_projects.csv \
  --threshold 8.9 \
  --score-operator gt \
  --require-exploit-available \
  --out policy_findings.csv \
  --failures-out policy_pull_failures.csv
```

Reachability is captured when fields are available, but is not required by default. Future AI-based reachability can be added behind `--reachability-mode ai`.

Optional policy filtering is supported with `--policy-name` or `--policy-rule-id`, but the direct high-risk criteria are sufficient when policy matching is not needed.

### 3. Datadog dry run

```bash
blackduck-findings-to-datadog \
  --findings policy_findings.csv \
  --event-mode project \
  --site datadoghq.com \
  --service blackduck \
  --source blackduck \
  --env prod
```

### 4. Datadog apply

```bash
blackduck-findings-to-datadog \
  --findings policy_findings.csv \
  --event-mode project \
  --site datadoghq.com \
  --service blackduck \
  --source blackduck \
  --env prod \
  --apply
```

Project event mode groups findings by Black Duck project. If findings disappear from the latest pull, the Datadog publisher marks them resolved in local state and sends success/recovery events.

## License

Use at your own risk, this is not an officially supported pathway.
