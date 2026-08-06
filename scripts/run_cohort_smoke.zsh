#!/bin/zsh
emulate -L zsh
setopt PIPE_FAIL

root="${0:A:h:h}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
cohort_id="smoke-${timestamp}"
result_dir="${root}/.cohort-smoke-results/${cohort_id}"
volume="blackduck-wintermute-cohort-smoke"
output_root="/var/lib/blackduck-wintermute"
cohort_dir="${output_root}/cohorts/${cohort_id}"
source_image="blackduck-wintermute-source:local"
jira_image="blackduck-wintermute-jira:local"
datadog_image="blackduck-wintermute-datadog:local"
source_container="wintermute-source-${timestamp:l}"
jira_container="wintermute-jira-${timestamp:l}"
datadog_container="wintermute-datadog-${timestamp:l}"
config_host="${root}/src/wintermute/jira/config/jira-rollup-config.json"
config_container="/etc/blackduck-wintermute/jira-rollup-config.json"

mkdir -p "${result_dir}"
printf '%s\n' "${result_dir}" \
  > "${root}/.cohort-smoke-results/latest-run.txt"

cleanup() {
  docker rm -f \
    "${source_container}" \
    "${jira_container}" \
    "${datadog_container}" \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

fail_run() {
  printf '%s\n' "$1" > "${result_dir}/status.txt"
  print -r -- "$1"
  exit 1
}

if [[ -z "${BLACKDUCK_URL:-}" || -z "${BLACKDUCK_API_TOKEN:-}" ]]; then
  if [[ -f "${root}/scripts/load_blackduck_env.zsh" ]]; then
    source "${root}/scripts/load_blackduck_env.zsh" ||
      fail_run "SETUP_FAILED:BLACKDUCK_CREDENTIALS"
  else
    fail_run "SETUP_FAILED:BLACKDUCK_CREDENTIALS"
  fi
fi

[[ -f "${config_host}" ]] ||
  fail_run "SETUP_FAILED:JIRA_CONFIG_NOT_FOUND"

docker build \
  --target source \
  --tag "${source_image}" \
  "${root}" > "${result_dir}/docker-source-build.log" 2>&1 ||
  fail_run "BUILD_FAILED:SOURCE"

docker build \
  --target jira \
  --tag "${jira_image}" \
  "${root}" > "${result_dir}/docker-jira-build.log" 2>&1 ||
  fail_run "BUILD_FAILED:JIRA"

docker build \
  --target datadog \
  --tag "${datadog_image}" \
  "${root}" > "${result_dir}/docker-datadog-build.log" 2>&1 ||
  fail_run "BUILD_FAILED:DATADOG"

docker volume inspect "${volume}" \
  > "${result_dir}/volume-before.json" 2>&1 ||
  docker volume create "${volume}" \
    > "${result_dir}/volume-create.log" 2>&1 ||
  fail_run "VOLUME_CREATE_FAILED"

docker run \
  --rm \
  --user 0:0 \
  --entrypoint /bin/sh \
  --mount "type=volume,source=${volume},target=${output_root}" \
  "${source_image}" \
  -c 'mkdir -p "$1" && chown -R 10001:10001 "$1" && chmod 0770 "$1"' \
  sh "${output_root}" \
  > "${result_dir}/volume-permissions.log" 2>&1 ||
  fail_run "VOLUME_PERMISSION_SETUP_FAILED"

docker run \
  --name "${source_container}" \
  --user 10001:10001 \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --cpus 4 \
  --memory 4g \
  --tmpfs "/tmp:rw,nosuid,size=1g,uid=10001,gid=10001,mode=1777" \
  --env "WINTERMUTE_OUTPUT_DIR=${output_root}" \
  --env "TMPDIR=/tmp" \
  --env BLACKDUCK_URL \
  --env BLACKDUCK_API_TOKEN \
  --mount "type=volume,source=${volume},target=${output_root}" \
  "${source_image}" \
  --scope parent-rollup \
  --strict \
  --resolve-bom-names \
  --workers 8 \
  --component-workers 2 \
  --page-limit 500 \
  --minimum-score 7 \
  --skip-policy-rule-details \
  --cohort-root "${output_root}/cohorts" \
  --cohort-id "${cohort_id}" \
  --summary-out "${output_root}/smoke/${cohort_id}/source-summary.json" \
  --insecure \
  > "${result_dir}/source.log" 2>&1

source_exit=$?
printf '%s\n' "${source_exit}" \
  > "${result_dir}/source-exit-code.txt"
(( source_exit == 0 )) ||
  fail_run "SOURCE_FAILED:${source_exit}"

docker run \
  --name "${jira_container}" \
  --user 10001:10001 \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --cpus 2 \
  --memory 2g \
  --tmpfs "/tmp:rw,nosuid,size=1g,uid=10001,gid=10001,mode=1777" \
  --env "WINTERMUTE_OUTPUT_DIR=${output_root}" \
  --env "TMPDIR=/tmp" \
  --mount "type=volume,source=${volume},target=${output_root}" \
  --mount "type=bind,source=${config_host},target=${config_container},readonly" \
  "${jira_image}" \
  --cohort "${cohort_dir}" \
  --dry-run \
  --strict \
  --config "${config_container}" \
  > "${result_dir}/jira.log" 2>&1

jira_exit=$?
printf '%s\n' "${jira_exit}" \
  > "${result_dir}/jira-exit-code.txt"
(( jira_exit == 0 )) ||
  fail_run "JIRA_FAILED:${jira_exit}"

docker run \
  --name "${datadog_container}" \
  --user 10001:10001 \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --cpus 2 \
  --memory 2g \
  --tmpfs "/tmp:rw,nosuid,size=1g,uid=10001,gid=10001,mode=1777" \
  --env "WINTERMUTE_OUTPUT_DIR=${output_root}" \
  --env "TMPDIR=/tmp" \
  --mount "type=volume,source=${volume},target=${output_root}" \
  "${datadog_image}" \
  --cohort "${cohort_dir}" \
  --dry-run \
  --strict \
  > "${result_dir}/datadog.log" 2>&1

datadog_exit=$?
printf '%s\n' "${datadog_exit}" \
  > "${result_dir}/datadog-exit-code.txt"
(( datadog_exit == 0 )) ||
  fail_run "DATADOG_FAILED:${datadog_exit}"

docker run \
  --rm \
  --user 10001:10001 \
  --entrypoint python \
  --mount "type=volume,source=${volume},target=${output_root},readonly" \
  "${source_image}" \
  -c '
import json
import sys
from pathlib import Path
from wintermute.blackduck.cohort import load_cohort

root = Path(sys.argv[1])
cohort_id = sys.argv[2]
cohort = load_cohort(root / "cohorts" / cohort_id)
source = json.loads(
    (root / "smoke" / cohort_id / "source-summary.json").read_text()
)
jira = json.loads(
    (
        root
        / "destinations"
        / "jira"
        / "runs"
        / cohort_id
        / "cohort-consumer-summary.json"
    ).read_text()
)
datadog = json.loads(
    (
        root
        / "destinations"
        / "datadog"
        / "runs"
        / cohort_id
        / "datadog-publish-plan.json"
    ).read_text()
)

print(
    json.dumps(
        {
            "cohort_id": cohort_id,
            "checksums_verified": True,
            "source": {
                "status": source.get("status"),
                "target_count": source.get("target_count"),
                "finding_count": source.get("finding_count"),
                "failure_count": source.get("failure_count"),
            },
            "jira": {
                "exit_code": jira.get("exit_code"),
                "dry_run": jira.get("dry_run"),
                "filtered_finding_count": jira.get("filtered_finding_count"),
                "projected_row_count": jira.get("projected_row_count"),
                "node_count": jira.get("node_count"),
            },
            "datadog": {
                "dry_run": datadog.get("dry_run"),
                "input_finding_count": datadog.get("input_finding_count"),
                "project_group_count": datadog.get("project_group_count"),
                "vulnerability_group_count": datadog.get(
                    "vulnerability_group_count"
                ),
                "event_count": datadog.get("event_count"),
            },
            "cohort": {
                "loaded_finding_count": len(cohort.findings),
                "scope_failure_count": len(cohort.scope_failures),
                "collection_failure_count": len(
                    cohort.collection_failures
                ),
            },
        },
        indent=2,
        sort_keys=True,
    )
)
' "${output_root}" "${cohort_id}" \
  > "${result_dir}/summary.json" 2> "${result_dir}/summary-error.log" ||
  fail_run "SUMMARY_VALIDATION_FAILED"

docker run \
  --rm \
  --user 10001:10001 \
  --entrypoint /bin/sh \
  --mount "type=volume,source=${volume},target=${output_root},readonly" \
  "${source_image}" \
  -c 'find "$1" -maxdepth 7 -type f | sort' \
  sh "${output_root}" \
  > "${result_dir}/artifacts.txt" 2>&1 ||
  fail_run "ARTIFACT_LIST_FAILED"

docker volume inspect "${volume}" \
  > "${result_dir}/volume-after.json" 2>&1

printf '%s\n' "0" > "${result_dir}/status.txt"
print
print "COHORT_SMOKE_OK"
print "Cohort: ${cohort_id}"
print "Volume: ${volume}"
print "Results: ${result_dir}"
cat "${result_dir}/summary.json"
exit 0
