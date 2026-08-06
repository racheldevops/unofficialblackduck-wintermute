<p align="center">
  <img src="docs/assets/wintermute-logo.png" alt="Wintermute" width="760">
</p>

# Project Wintermute

**Black Duck in. Coordinated security workflows out.**

Wintermute turns Black Duck SCA data into one normalized, checksum-protected cohort that can drive Jira, Datadog, and future integrations. It discovers parent and child project lineage, collects each affected project version once, preserves product context, and gives every destination a consistent security snapshot without repeatedly loading Black Duck.

It is built for production engineering teams: concurrent collection, deterministic identities, persistent caching, destination-scoped credentials, dry-run-first publishing, non-root containers, and Kubernetes cohort orchestration using Argo. Jira produces vulnerability-remediation hierarchies, while Datadog produces concise high-risk vulnerability events from the same underlying findings.

A representative large-instance cold run improved from about 17 minutes to about 6 minutes while preserving the same relationships, findings, and Jira hierarchy. The cohort model also separates Black Duck collection from destination delivery, so integrations can evolve independently without duplicating source logic.

## Quick start

<pre>
python3.12 -m virtualenv .venv
source .venv/bin/activate
python -m pip install -e .
blackduck-wintermute-pull --help
</pre>

For production deployment, start with the [cohort deployment guide](READMEs/COHORT_DEPLOYMENT_README.md). Existing Jira and Datadog commands remain available as compatibility workflows.

> Wintermute is an unofficial Black Duck integration project. Validate dry-run output and customer configuration before enabling destination changes.
