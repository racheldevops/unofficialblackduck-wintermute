# Jira hierarchy planning

Create a normalized Jira hierarchy plan from Black Duck vulnerability rollup findings.

The hierarchy planner reads the Jira workflow findings file, groups findings into deterministic Epic and Task nodes, and writes reusable JSON and CSV planning files.

The planner does not call Jira and does not call Black Duck.

## Current package layout

The project is organized into two Python package areas:

    src/harness/
    ├── jira/
    │   ├── config/
    │   │   └── jira-rollup-config.json
    │   ├── find_parent_projects.py
    │   ├── subp_vuln_rollup.py
    │   ├── findings_hierarchy_plan.py
    │   └── findings_to_jira.py
    ├── datadog/
    │   ├── policy_vuln_find.py
    │   ├── policy_vuln_pull.py
    │   └── findings_to_datadog.py
    └── paths.py

Jira workflow outputs are written under:

    .harness/jira/

Datadog workflow outputs are written under:

    .harness/datadog/

The output root can be changed with the HARNESS_OUTPUT_DIR environment variable.

## Running the modules

Each workflow file is an importable Python module with a main function.

The installed command and module command execute the same source code.

Installed hierarchy planner command:

    blackduck-hierarchy-plan

Equivalent Python module command:

    python -m harness.jira.findings_hierarchy_plan

Installed Jira publisher command:

    blackduck-findings-to-jira

Equivalent Python module command:

    python -m harness.jira.findings_to_jira

For IntelliJ, use Module name as the run target and select the project virtual environment.

Hierarchy planner module name:

    harness.jira.findings_hierarchy_plan

Jira publisher module name:

    harness.jira.findings_to_jira

Working directory:

    $PROJECT_DIR$

The package should be installed as editable in the project virtual environment:

    source .venv/bin/activate
    python -m pip install -e .

An editable install means normal Python source changes are immediately available. Reinstall after changing package metadata or command entry points.

## Jira workflow

The current Jira pipeline is:

    .harness/jira/parent_projects.csv
        |
        v
    harness.jira.subp_vuln_rollup
        |
        v
    .harness/jira/findings.csv
        |
        v
    harness.jira.findings_hierarchy_plan
        |
        v
    .harness/jira/jira-hierarchy-plan.json
        |
        v
    harness.jira.findings_to_jira
        |
        v
    Jira Epics, Tasks, fields, and relationships

## Default files

| Purpose | Default path |
|---|---|
| Parent and child relationships | .harness/jira/parent_projects.csv |
| Rollup findings | .harness/jira/findings.csv |
| Hierarchy plan | .harness/jira/jira-hierarchy-plan.json |
| Hierarchy summary | .harness/jira/jira-hierarchy-summary.csv |
| Flattened hierarchy nodes | .harness/jira/jira-hierarchy-nodes.csv |
| Jira publish plan | .harness/jira/jira-rollup-plan.json |
| Jira publish results | .harness/jira/jira-rollup-results.csv |
| Jira publisher state | .harness/jira/state/jira-rollup-state.json |
| Parent relationship cache | .harness/jira/cache/parent_projects_cache.json |
| Vulnerability rollup cache | .harness/jira/cache/subp_vuln_rollup_cache.json |

Old files in the repository root are no longer the default runtime inputs or outputs.

## Default hierarchy model

The default hierarchy mode is:

    vulnerability-project

The default Jira shape is:

    Epic: one CVE or vulnerability
    └── Task: CVE plus directly affected Black Duck project/version

Example hierarchy:

    [Black Duck] CVE-2018-1000620
    └── Black Duck: BLOCKER Alert - VUMA-TestProject - version 1.0.0 - Apache Log4j version 1.1.3

The planner uses the internal node type story for publisher compatibility. In vulnerability-project mode, story nodes are published as Jira Tasks by default.

| Node type | Jira meaning | Grouping |
|---|---|---|
| epic | CVE or vulnerability Epic | One per vulnerability ID |
| story | Affected project-version Task | One per vulnerability, affected project, affected version, and affected version URL |
| vulnerability | Not generated in default mode | Count is zero |

## Affected project and version

The directly affected project is the child or subproject in the rollup finding.

The mapping is:

    affected_project = subproject
    affected_version = subproject_version
    affected_project_version_href = subproject_version_href

For the requested title:

    Black Duck: BLOCKER Alert - VUMA-TestProject - version 1.0.0 - Apache Log4j version 1.1.3

The fields mean:

| Title value | Pipeline source |
|---|---|
| BLOCKER | Configured alert display severity |
| VUMA-TestProject | affected_project, originally subproject |
| 1.0.0 | affected_version, originally subproject_version |
| Apache Log4j | component |
| 1.1.3 | component_version |

The parent project and parent version remain available for traceability, descriptions, filters, and CSV output. They do not drive the default Task grouping or the requested Task title.

## Task title configuration

The Jira publisher renders Task titles using the hierarchy story summary template in:

    src/harness/jira/config/jira-rollup-config.json

The default template is:

    Black Duck: {alert_severity} Alert - {affected_project} - version {affected_version} - {component_summary}

For a Task containing one affected component, component_summary becomes:

    Apache Log4j version 1.1.3

The complete title becomes:

    Black Duck: BLOCKER Alert - VUMA-TestProject - version 1.0.0 - Apache Log4j version 1.1.3

If a CVE affects multiple components in the same project version, the planner still creates one Task. The title is summarized rather than choosing one arbitrary component.

Example:

    Black Duck: BLOCKER Alert - VUMA-TestProject - version 1.0.0 - 3 affected components

All affected components and versions remain in the Task description and hierarchy context.

## BLOCKER mapping

BLOCKER is treated as a configurable Jira title display value. It is not assumed to be a native Black Duck vulnerability severity.

Black Duck vulnerability severity values normally include:

    CRITICAL
    HIGH
    MEDIUM
    LOW

The default title mapping is:

    CRITICAL -> BLOCKER
    HIGH     -> HIGH
    MEDIUM   -> MEDIUM
    LOW      -> LOW
    UNKNOWN  -> UNKNOWN

The mapping is configured under:

    issue.alert_severity_by_severity

This display mapping affects titles. It does not change the original severity stored in findings, node context, labels, statistics, or priority selection.

If the customer confirms that BLOCKER comes from a Black Duck policy rule rather than a display mapping, policy severity can be added as a separate source field later.

## Neutral planner summaries and final Jira titles

The hierarchy planner creates neutral node summaries so the plan remains reusable.

Example neutral Task summary:

    CVE-2018-1000620 Project VUMA-TestProject 1.0.0

The Jira publisher applies the configured Task title when it builds the Jira REST payload.

Therefore:

- jira-hierarchy-plan.json can contain the neutral planner summary.
- jira-rollup-plan.json contains the final Jira fields and configured title.
- The Jira issue receives the configured title when published.
- Changing the display template does not change deterministic hierarchy IDs.

## Entity custom field

The vulnerability rollup attempts to read the Black Duck project custom field named:

    E+H Entity

The lookup is performed for the directly affected Black Duck project and cached per project during the run.

The value is written to findings as:

    entity

The hierarchy planner propagates Entity into affected project-version Task context.

Example Task context:

    {
      "affected_project": "VUMA-TestProject",
      "affected_version": "1.0.0",
      "entity": "Example Entity"
    }

Entity is optional by default so the workflow can run against Black Duck instances that do not define the customer field.

To require Entity for every affected project:

    blackduck-vuln-rollup --require-entity

The custom-field name can be changed:

    blackduck-vuln-rollup \
      --entity-custom-field "E+H Entity"

Entity is not part of hierarchy grouping or deterministic IDs. Changing an Entity value should update the existing Jira Task rather than create a duplicate Task.

## Jira Entity field mapping

The Jira custom field ID must be supplied by the customer or Jira administrator.

The mapping is configured under:

    hierarchy.field_mappings.entity

Example for a Jira text field:

    {
      "entity": {
        "field_id": "customfield_12345",
        "source": "entity",
        "node_types": ["story"],
        "value_type": "text"
      }
    }

Until field_id is populated, Entity remains in the plan and description but is not sent as a separate Jira custom field.

Supported mapping value types include:

| Type | Jira payload behavior |
|---|---|
| text | Sends a string |
| number | Sends a numeric value |
| option | Sends an object containing value |
| array | Sends a list |

The Jira Default and Entity screen tabs are controlled by Jira administration. The publisher populates fields but does not create or rearrange Jira screen tabs.

## Existing Jira issue updates

Existing Jira issues are skipped by default.

To synchronize configured managed fields such as Entity, Project Name, Project Version, CVSS Vector, and CVSS Score:

    blackduck-findings-to-jira \
      --hierarchy-plan .harness/jira/jira-hierarchy-plan.json \
      --sync-existing-fields \
      --dry-run

To apply the updates:

    blackduck-findings-to-jira \
      --hierarchy-plan .harness/jira/jira-hierarchy-plan.json \
      --sync-existing-fields \
      --apply

Field synchronization can also be enabled in configuration with:

    hierarchy.sync_existing_fields = true

Always inspect the dry-run plan before applying updates.

## CVSS data

The rollup now supports:

    score
    score_field
    cvss_vector

The hierarchy Task contains:

- The maximum numeric score across its grouped findings
- The available unique CVSS vectors
- Original component-level scores in the Task description

The default Jira field mappings include placeholders for:

    project_name
    project_version
    cvss_vector
    cvss_score
    entity

Each Jira field mapping remains disabled until its field_id is configured.

## Input fields

The findings CSV must include:

    parent_project
    parent_version
    parent_version_href
    subproject_path
    subproject
    subproject_version
    subproject_version_href
    relationship_detection_method
    component
    component_version
    vulnerability
    score_field
    score
    severity
    blackduck_url
    rollup_key

The following fields are optional for compatibility with older findings files:

    entity
    cvss_vector

If rollup_key is blank, it is derived from:

    parent_project
    parent_version
    subproject
    subproject_version
    component
    component_version
    vulnerability

## Default grouping and deterministic IDs

### CVE Epic

Grouping key:

    vulnerability

External ID:

    bd_cve_<sha256 of vulnerability>

Labels include:

    blackduck
    subproject_rollup
    bd_rollup_cve
    bd_cve_<short hash>
    bd_sev_<highest severity>

### Affected project-version Task

Grouping key:

    vulnerability
    affected_project
    affected_version
    affected_project_version_href

External ID:

    bd_cve_project_<sha256 of grouping key>

Labels include:

    blackduck
    subproject_rollup
    bd_rollup_project_version
    bd_cve_<short hash>
    bd_project_version_<short hash>
    bd_sev_<highest severity>

Entity, CVSS vector, component names, display severity, and Jira title text are not included in deterministic IDs.

## Plan schema

The current hierarchy plan schema version is:

    3

A default Task context can include:

    {
      "vulnerability": "CVE-2018-1000620",
      "severity": "CRITICAL",
      "affected_project": "VUMA-TestProject",
      "affected_version": "1.0.0",
      "affected_project_version_href": "https://blackduck.example/api/projects/.../versions/...",
      "subproject": "VUMA-TestProject",
      "subproject_version": "1.0.0",
      "components": ["Apache Log4j"],
      "component_versions": ["1.1.3"],
      "entity": "Example Entity",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }

Node statistics include:

    finding_count
    component_count
    vulnerability_count
    affected_project_version_count
    critical_count
    high_count
    medium_count
    low_count
    unknown_count
    max_score
    min_score
    average_score

Epic nodes also include:

    child_count

## Planner output CSV fields

The hierarchy summary CSV includes Epic and Task nodes.

Important fields include:

    hierarchy_mode
    node_type
    external_id
    parent_external_id
    lookup_label
    summary
    vulnerability
    entity
    cvss_vector
    affected_project
    affected_version
    affected_project_version_href
    parent_project
    parent_version
    subproject
    subproject_version
    component_count
    max_score

The nodes CSV contains every generated node and also includes:

    components
    component_versions
    blackduck_url
    blackduck_urls
    rollup_key
    rollup_keys
    entity
    cvss_vector

## Common planner run

The default command uses the default findings and output paths:

    blackduck-hierarchy-plan

Equivalent module command:

    python -m harness.jira.findings_hierarchy_plan

Explicit command:

    blackduck-hierarchy-plan \
      --findings .harness/jira/findings.csv \
      --hierarchy-mode vulnerability-project \
      --plan-out .harness/jira/jira-hierarchy-plan.json \
      --summary-out .harness/jira/jira-hierarchy-summary.csv \
      --nodes-out .harness/jira/jira-hierarchy-nodes.csv

## Focused hierarchy test

Example focused run:

    blackduck-hierarchy-plan \
      --findings .harness/jira/findings.csv \
      --only-parent-project "cc-goat" \
      --only-parent-version "v2" \
      --only-subproject "juicy_cam.juiced" \
      --only-vulnerability "CVE-2018-1000620"

Expected shape:

    CVE Epic nodes:          1
    Project-version Tasks:   1 or more
    Vulnerability nodes:     0

## Limited smoke test

    blackduck-hierarchy-plan \
      --limit 25 \
      --debug

This writes the normal files under .harness/jira without contacting Jira or Black Duck.

## Targeting filters

| Flag | Description |
|---|---|
| --only-parent-project | Filter by exact parent project context |
| --only-parent-version | Filter by exact parent version context |
| --only-subproject | Filter by directly affected project |
| --only-vulnerability | Filter by exact vulnerability ID |
| --limit | Process only the first N deduplicated findings |

Filters are applied before nodes are grouped.

Required parent Epics are retained when matching Task nodes are selected.

## Legacy hierarchy model

The project-centered legacy model remains available:

    blackduck-hierarchy-plan \
      --hierarchy-mode project-subproject-vulnerability \
      --plan-out .harness/jira/jira-hierarchy-plan-legacy.json \
      --summary-out .harness/jira/jira-hierarchy-summary-legacy.csv \
      --nodes-out .harness/jira/jira-hierarchy-nodes-legacy.csv

Legacy shape:

    Epic: parent project/version
    └── Story: child/subproject version
        └── Vulnerability issue or subtask

Legacy deterministic IDs remain based on parent, child, and rollup identity.

## Jira publisher dry run

Run the publisher against the hierarchy plan:

    blackduck-findings-to-jira \
      --hierarchy-plan .harness/jira/jira-hierarchy-plan.json \
      --config src/harness/jira/config/jira-rollup-config.json \
      --dry-run \
      --debug

Equivalent module command:

    python -m harness.jira.findings_to_jira \
      --hierarchy-plan .harness/jira/jira-hierarchy-plan.json \
      --dry-run \
      --debug

The dry-run output includes the complete Jira fields object. This allows verification of:

- Final configured Task title
- Parent relationship
- Labels
- Priority
- Entity custom field
- Project custom fields
- CVSS score and vector fields

No Jira issues, field updates, or links are applied in dry-run mode.

## Applying Jira changes

After validating the dry-run output:

    blackduck-findings-to-jira \
      --hierarchy-plan .harness/jira/jira-hierarchy-plan.json \
      --apply

To update managed fields on existing Jira issues:

    blackduck-findings-to-jira \
      --hierarchy-plan .harness/jira/jira-hierarchy-plan.json \
      --sync-existing-fields \
      --apply

Jira URL and credentials are provided through configuration and environment variables.

Common environment variables:

    JIRA_URL
    JIRA_USER
    JIRA_API_TOKEN
    JIRA_PAT

## Notes

- The planner does not require Jira credentials.
- The planner does not create Jira issues.
- The planner does not call Black Duck.
- The Black Duck rollup retrieves Entity and vulnerability details.
- The planner normalizes findings into deterministic hierarchy nodes.
- The Jira publisher applies issue types, final titles, fields, priorities, and parent relationships.
- Installed commands and Python module commands use the same source modules.
- Jira UI screen tabs must be configured by a Jira administrator.
- Use a Jira dry run before applying new field mappings or title templates.
