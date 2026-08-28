# Project Wintermute

<p align="center">
  <img src="docs/assets/wintermute-logo.png" alt="Wintermute" width="760">
</p>

<p align="center">
  <strong>Black Duck in. Coordinated security workflows out.</strong>
  <br><br>
  <em>Designed to accelerate Black Duck adoption through repeatable security and remediation workflows.</em>
</p>

---

Wintermute collects and normalizes Black Duck SCA data for Jira, Datadog, SCM coverage, and controlled Black Duck remediation actions.

The project provides concurrent collection, deterministic identities, persistent caches, checksum-protected artifacts, dry-run-first publishing, non-root containers, and Kubernetes orchestration.

## Workflows

| Workflow | Purpose |
|---|---|
| Cohort | Collect Black Duck once and deliver the same immutable snapshot to Jira and Datadog |
| SCM coverage | Inventory GitHub and GitLab repositories and reconcile them with Black Duck registration and scan evidence |
| CIP remediation | Prove Linux CIP fixes from GitLab evidence and create controlled Black Duck remediation actions |
| Compatibility commands | Run standalone Jira, Datadog, parent discovery, and candidate workflows |

## Quick start

    python3.12 -m virtualenv .venv
    source .venv/bin/activate
    python -m pip install -e .
    blackduck-wintermute-pull --help

## Documentation

- Cohort deployment: READMEs/COHORT_DEPLOYMENT_README.md
- Black Duck collection: READMEs/BLACKDUCK_COLLECTION_README.md
- SCM coverage: READMEs/SCM_COVERAGE_README.md
- CIP remediation: READMEs/CIP_REMEDIATION_README.md
- Architecture: READMEs/ARCHITECTURE.md
- Kubernetes deployment: READMEs/KUBERNETES_DEPLOYMENT_README.md

## Validation

Run the local regression suite:

    python -m pytest -q tests
    python scripts/validate_entrypoints.py
    python scripts/validate_release.py --skip-docker

Run the read-only pre-merge endpoint smoke:

    python scripts/run_premerge_smoke.py --insecure

Use a customer CA bundle instead of insecure TLS in production.

## Black Duck validation baseline

Wintermute tracks and is tested against the latest Black Duck SCA release available to the project, including pre-release builds where available.

Older releases are outside the tested baseline and may behave differently as APIs evolve.

## Black Duck SCA hardware

The minimum Black Duck SCA hardware specification for Wintermute at its slowest request pace is:

    sizes-gen04/250sph.yaml

The recommended specification is:

    sizes-gen05/500sph.yaml

See the official Black Duck SCA hardware scaling guidance for production sizing.

> Wintermute is an unofficial DevSecOps and GitOps project and is not supported by Black Duck. Review dry-run output and customer configuration before enabling changes.
