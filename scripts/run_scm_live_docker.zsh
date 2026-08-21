#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

root="${0:A:h:h}"
image="blackduck-wintermute:scm-live-test"
output_dir="${root}/.scm-live-test-output"
run_id="scm-live-$(date -u +%Y%m%dT%H%M%SZ)"
allow_partial="${SCM_SMOKE_ALLOW_PARTIAL:-false}"
insecure="${SCM_SMOKE_INSECURE:-true}"

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"
: "${GITHUB_ORG:?GITHUB_ORG is required}"
: "${BLACKDUCK_URL:?BLACKDUCK_URL is required}"
: "${BLACKDUCK_API_TOKEN:?BLACKDUCK_API_TOKEN is required}"

case "${allow_partial:l}" in
  true|false)
    ;;
  *)
    print -u2 "SCM_SMOKE_ALLOW_PARTIAL must be true or false"
    exit 2
    ;;
esac

case "${insecure:l}" in
  true|false)
    ;;
  *)
    print -u2 "SCM_SMOKE_INSECURE must be true or false"
    exit 2
    ;;
esac

mkdir -p "${output_dir}"
chmod 0777 "${output_dir}"

run_with_heartbeat() {
  local label="$1"
  shift

  local process_id
  local command_exit_code

  "$@" &
  process_id=$!

  while kill -0 "${process_id}" 2>/dev/null; do
    sleep 10

    if kill -0 "${process_id}" 2>/dev/null; then
      print "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ${label} still running..."
    fi
  done

  if wait "${process_id}"; then
    command_exit_code=0
  else
    command_exit_code=$?
  fi

  return "${command_exit_code}"
}

print_snapshot_diagnostics() {
  local snapshot_directory="$1"

  SNAPSHOT_DIRECTORY="${snapshot_directory}" python - <<'PY'
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterator


root = Path(os.environ["SNAPSHOT_DIRECTORY"])

print()
print("Snapshot diagnostics")
print("====================")
print("Directory:", root)

if not root.is_dir():
    print("Snapshot directory does not exist")
    raise SystemExit(0)


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        print(f"Could not read {path.name}: {error}")
        return {}

    return payload if isinstance(payload, dict) else {}


def failure_records(
    value: Any,
    location: str,
) -> Iterator[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        if (
            str(value.get("stage") or "").strip()
            and str(value.get("error") or "").strip()
        ):
            yield location, value

        for key, nested in value.items():
            child_location = (
                f"{location}.{key}"
                if location
                else str(key)
            )
            yield from failure_records(
                nested,
                child_location,
            )

    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from failure_records(
                nested,
                f"{location}[{index}]",
            )


metadata = read_json(root / "metadata.json")

if metadata:
    print("Status:", metadata.get("status"))
    print("Failure count:", metadata.get("failure_count"))

seen: set[tuple[str, str, str]] = set()
found = False

for filename in (
    "failures.json",
    "provider-evidence.json",
    "onboarding-controls.json",
):
    payload = read_json(root / filename)

    for location, failure in failure_records(
        payload,
        filename,
    ):
        stage = str(
            failure.get("stage") or "unknown"
        )
        error = str(
            failure.get("error") or "unknown"
        )
        resource = str(
            failure.get("name_with_owner")
            or failure.get("project")
            or failure.get("repository_id")
            or ""
        )
        identity = (
            stage,
            error,
            resource,
        )

        if identity in seen:
            continue

        seen.add(identity)
        found = True

        print()
        print(f"[{location}]")
        print("Stage:", stage)

        if resource:
            print("Resource:", resource)

        print("Error:", error)

if not found:
    print("No detailed failures found")
PY
}

cd "${root}"

print "Building ${image}..."

build_command=(
  docker
  build
  --progress=plain
  --pull
  --target
  runtime
  --tag
  "${image}"
  .
)

"${build_command[@]}"

docker_options=(
  --rm
  --read-only
  --cpus
  2
  --memory
  2g
  --tmpfs
  "/tmp:rw,size=256m"
  --mount
  "type=bind,src=${output_dir},dst=/output"
  --env
  GITHUB_TOKEN
  --env
  GITHUB_ORG
  --env
  BLACKDUCK_URL
  --env
  BLACKDUCK_API_TOKEN
  --env
  "WINTERMUTE_OUTPUT_DIR=/output"
  --env
  "TMPDIR=/tmp"
  --env
  "PYTHONUNBUFFERED=1"
  --env
  "WINTERMUTE_BLACKDUCK_REQUEST_INTERVAL_SECONDS=0.5"
  --env
  "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_THRESHOLD=5"
  --env
  "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_WINDOW_SECONDS=60"
)

if [[ -n "${GITHUB_GRAPHQL_URL:-}" ]]; then
  docker_options+=(
    --env
    GITHUB_GRAPHQL_URL
  )
fi

if [[ -n "${GITHUB_REST_URL:-}" ]]; then
  docker_options+=(
    --env
    GITHUB_REST_URL
  )
fi

tls_options=()

if [[ "${insecure:l}" == "true" ]]; then
  tls_options+=(--insecure)

  print
  print "WARNING: TLS certificate verification is disabled for this test."
fi

print
print "Phase 1/2: GitHub GraphQL and REST inventory"
print "Organization: ${GITHUB_ORG}"
print "Snapshot ID: ${run_id}"

inventory_command=(
  docker
  run
  "${docker_options[@]}"
  --name
  "wintermute-scm-inventory-${run_id}"
  --entrypoint
  python
  "${image}"
  -u
  -m
  wintermute.scm
  --organization
  "${GITHUB_ORG}"
  --snapshot-root
  /output/scm/inventory/snapshots
  --snapshot-id
  "${run_id}"
  --page-size
  100
  --evidence-workers
  1
  --timeout
  30
  --retries
  1
  --retry-delay
  2
  --max-hours
  2
  "${tls_options[@]}"
)

if run_with_heartbeat \
  "GitHub SCM inventory" \
  "${inventory_command[@]}"
then
  inventory_exit_code=0
else
  inventory_exit_code=$?
fi

inventory_snapshot="${output_dir}/scm/inventory/snapshots/${run_id}"

if (( inventory_exit_code > 1 )); then
  print_snapshot_diagnostics \
    "${inventory_snapshot}"

  print -u2
  print -u2 "FAIL: GitHub SCM inventory exited ${inventory_exit_code}"
  exit "${inventory_exit_code}"
fi

if (( inventory_exit_code == 1 )); then
  print
  print "WARNING: GitHub inventory completed with partial provider evidence."

  print_snapshot_diagnostics \
    "${inventory_snapshot}"
fi

print
print "Phase 2/2: bounded Black Duck coverage and direct scan evidence"

coverage_command=(
  docker
  run
  "${docker_options[@]}"
  --name
  "wintermute-scm-coverage-${run_id}"
  --entrypoint
  python
  "${image}"
  -u
  -m
  wintermute.scm.coverage
  --scm-snapshot
  "/output/scm/inventory/snapshots/${run_id}"
  --coverage-root
  /output/scm/coverage/snapshots
  --snapshot-id
  "${run_id}"
  --collect-direct-scan-evidence
  --max-projects
  2
  --max-versions
  5
  --workers
  1
  --scan-evidence-workers
  1
  --page-limit
  100
  --timeout
  30
  --retries
  1
  --retry-delay
  2
  --freshness-sla-days
  30
  --retain-snapshots
  3
  "${tls_options[@]}"
)

if run_with_heartbeat \
  "Black Duck SCM coverage" \
  "${coverage_command[@]}"
then
  coverage_exit_code=0
else
  coverage_exit_code=$?
fi

coverage_snapshot="${output_dir}/scm/coverage/snapshots/${run_id}"

if (( coverage_exit_code > 1 )); then
  print_snapshot_diagnostics \
    "${coverage_snapshot}"

  print -u2
  print -u2 "FAIL: Black Duck SCM coverage exited ${coverage_exit_code}"
  exit "${coverage_exit_code}"
fi

if (( coverage_exit_code == 1 )); then
  print
  print "WARNING: Black Duck coverage completed with partial evidence."

  print_snapshot_diagnostics \
    "${coverage_snapshot}"
fi

print
print "SCM live endpoint test completed"
print "Inventory exit code: ${inventory_exit_code}"
print "Coverage exit code:  ${coverage_exit_code}"
print "Output: ${output_dir}"

find "${output_dir}" \
  -type f \
  -print |
sort

partial_detected="false"

if (( inventory_exit_code == 1 )); then
  partial_detected="true"
fi

if (( coverage_exit_code == 1 )); then
  partial_detected="true"
fi

if [[ "${partial_detected}" == "true" ]]; then
  if [[ "${allow_partial:l}" != "true" ]]; then
    print -u2
    print -u2 "FAIL: test completed with partial evidence"
    print -u2 "Review the diagnostics above."
    print -u2 "Set SCM_SMOKE_ALLOW_PARTIAL=true only if the failure is expected."
    exit 1
  fi
fi

print
print "PASS: SCM live endpoint smoke test completed"
