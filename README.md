# Project Wintermute
<p align="center">
  <img src="docs/assets/wintermute-logo.png" alt="Wintermute" width="760">
</p>


<p align="center">
  <strong>Black Duck in. Coordinated security workflows out.</strong>
  <br><br>
  <em>Designed to accelerate Black Duck adoption - from initial visibility to repeatable, automated remediation workflows.</em>
</p>

---
Wintermute turns Black Duck SCA data into one normalized, checksum-protected cohort that can drive Jira, Datadog, and future integrations. It discovers parent and child project lineage, collects each affected project version once, preserves product context, and gives every destination a consistent security snapshot without repeatedly loading Black Duck.

It is built for enterprise engineering teams: concurrent collection, deterministic identities, persistent caching, destination-scoped credentials, dry-run-first publishing, non-root containers, and Kubernetes cohort orchestration using Argo. Jira produces vulnerability-remediation hierarchies, while Datadog produces concise high-risk vulnerability events from the same underlying findings.

Cut a representative large-instance workflow from 17 minutes to 3 minutes with the same findings, relationships, and hierarchy. Collect once, deliver anywhere.

## Quick start

<pre>
python3.12 -m virtualenv .venv
source .venv/bin/activate
python -m pip install -e .
blackduck-wintermute-pull --help
</pre>

For production deployment, start with the [cohort deployment guide](READMEs/COHORT_DEPLOYMENT_README.md). Existing Jira and Datadog commands remain available as compatibility workflows.

## Black Duck validation baseline

Wintermute tracks and is tested against the latest Black Duck SCA release available to the project, including pre-release builds where available.

Older Black Duck releases are outside the tested baseline and may behave differently as APIs evolve. This describes the versions exercised during development, not a compatibility guarantee.

## Black Duck SCA Hardware Spec

The minimum BDSCA hardware spec to run wintermute at its slowest pace (7,500 api requests/hr) is: <p>
```"sizes-gen05/250sph.yaml"```

The recommended spec is: <p>
``` "sizes-gen05/500sph.yaml" ```

Please check the official BDSCA Hardware guide [here](https://docs.blackduck.com/r/blackduck/black-duck-compatibility-reference/black-duck-sca-hardware-scaling-guidelines.html)

> Wintermute is an unofficial personal DevSecOps/GitOps project and is not supported by Black Duck. Validate dry-run output and customer configuration before enabling destination changes. Contribution is welcomed.
