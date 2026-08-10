#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

root="${0:A:h:h:h}"
state_dir="${WINTERMUTE_K8S_STATE_DIR:-${HOME}/.local/state/blackduck-wintermute}"
manifest="${state_dir}/rendered-jira-pipeline.yaml"
latest_job_file="${state_dir}/latest-jira-job.txt"

namespace="${KUBE_NAMESPACE:-blackduck-wintermute}"
context="${KUBE_CONTEXT:-}"
registry_host="${REGISTRY_HOST:-}"
registry_repository="${REGISTRY_REPOSITORY:-}"
image_tag="${IMAGE_TAG:-}"
jira_url="${JIRA_URL:-}"
jira_project_key="${JIRA_PROJECT_KEY:-}"
pipeline_mode="${PIPELINE_MODE:-dry-run}"
confirm_apply="${CONFIRM_APPLY:-}"
max_create="${MAX_CREATE:-10}"
pvc_size="${PVC_SIZE:-10Gi}"
workers="${WORKERS:-2}"
parent_workers="${PARENT_WORKERS:-${workers}}"
rollup_workers="${ROLLUP_WORKERS:-${workers}}"
schedule="${CRON_SCHEDULE:-0 2 * * *}"
timezone="${CRON_TIMEZONE:-Etc/UTC}"
jira_insecure="${JIRA_INSECURE:-false}"
enable_schedule="${ENABLE_SCHEDULE:-false}"
wait_timeout="${JOB_TIMEOUT_SECONDS:-3600}"

mkdir -p "${state_dir}"

fail() {
  print -u2 -- "ERROR: $*"
  return 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 ||
    fail "Required command not found: $1"
}

resolve_image_tag() {
  if [[ -z "${image_tag}" ]]; then
    image_tag="$(
      git -C "${root}" rev-parse HEAD
    )"
  fi
}

require_context() {
  require_command kubectl

  [[ -n "${context}" ]] ||
    fail "Set KUBE_CONTEXT explicitly"

  kubectl --context "${context}" \
    cluster-info >/dev/null
}

require_image_settings() {
  [[ -n "${registry_host}" ]] ||
    fail "Set REGISTRY_HOST"

  [[ -n "${registry_repository}" ]] ||
    fail "Set REGISTRY_REPOSITORY"

  resolve_image_tag
}

require_render_settings() {
  require_image_settings

  [[ -n "${jira_url}" ]] ||
    fail "Set JIRA_URL"

  [[ -n "${jira_project_key}" ]] ||
    fail "Set JIRA_PROJECT_KEY"

  if [[ "${pipeline_mode}" == "apply" ]]; then
    [[ "${confirm_apply}" == "APPLY" ]] ||
      fail "Apply mode requires CONFIRM_APPLY=APPLY"
  fi
}

k() {
  kubectl \
    --context "${context}" \
    "$@"
}

image_name() {
  print -- "${registry_host%/}/${registry_repository#/}:${image_tag}"
}

preflight() {
  require_context

  print "Context: ${context}"
  print "Namespace: ${namespace}"
  print

  k get nodes -o wide
  print
  k get storageclass
  print
  k auth can-i create cronjobs.batch \
    --namespace "${namespace}"
  k auth can-i create jobs.batch \
    --namespace "${namespace}"
  k auth can-i create persistentvolumeclaims \
    --namespace "${namespace}"
  k auth can-i create secrets \
    --namespace "${namespace}"
}

build_push() {
  require_command docker
  require_image_settings

  image="$(image_name)"

  print "Building ${image}"
  docker build \
    --pull \
    --target runtime \
    --tag "${image}" \
    "${root}"

  docker run \
    --rm \
    "${image}" \
    --help >/dev/null

  print "Pushing ${image}"
  docker push "${image}"
}

configure() {
  require_context
  require_image_settings

  k create namespace "${namespace}" \
    --dry-run=client \
    --output yaml |
    k apply --filename -

  blackduck_url="${BLACKDUCK_URL:-}"
  jira_url="${jira_url}"
  jira_project_key="${jira_project_key}"

  if [[ -z "${blackduck_url}" ]]; then
    read -r "blackduck_url?Black Duck URL: "
  fi

  read -r -s \
    "blackduck_token?Black Duck API token: "
  print

  if [[ -z "${jira_url}" ]]; then
    read -r "jira_url?Jira URL: "
  fi

  if [[ -z "${jira_project_key}" ]]; then
    read -r \
      "jira_project_key?Jira project key: "
  fi

  read -r "jira_user?Jira user: "
  read -r -s "jira_token?Jira API token: "
  print

  [[ -n "${blackduck_url}" ]] ||
    fail "Black Duck URL is required"
  [[ -n "${blackduck_token}" ]] ||
    fail "Black Duck token is required"
  [[ -n "${jira_url}" ]] ||
    fail "Jira URL is required"
  [[ -n "${jira_project_key}" ]] ||
    fail "Jira project key is required"
  [[ -n "${jira_user}" ]] ||
    fail "Jira user is required"
  [[ -n "${jira_token}" ]] ||
    fail "Jira token is required"

  export JIRA_URL="${jira_url}"
  export JIRA_PROJECT_KEY="${jira_project_key}"

  NAMESPACE="${namespace}" \
  BLACKDUCK_URL="${blackduck_url%/}" \
  BLACKDUCK_API_TOKEN="${blackduck_token}" \
  JIRA_URL="${jira_url%/}" \
  JIRA_USER="${jira_user}" \
  JIRA_API_TOKEN="${jira_token}" \
    python - <<'PY' |
import base64
import json
import os


def encoded(value: str) -> str:
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("ascii")


print(
    json.dumps(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": (
                    "blackduck-wintermute-"
                    "credentials"
                ),
                "namespace": os.environ[
                    "NAMESPACE"
                ],
            },
            "type": "Opaque",
            "data": {
                name: encoded(
                    os.environ[name]
                )
                for name in (
                    "BLACKDUCK_URL",
                    "BLACKDUCK_API_TOKEN",
                    "JIRA_URL",
                    "JIRA_USER",
                    "JIRA_API_TOKEN",
                )
            },
        }
    )
)
PY
    k apply --filename -

  unset blackduck_token jira_token

  read -r \
    "registry_user?Registry username "\
"(blank for cluster-integrated registry): "

  registry_password=""

  if [[ -n "${registry_user}" ]]; then
    read -r -s \
      "registry_password?Registry password: "
    print
  fi

  NAMESPACE="${namespace}" \
  REGISTRY_HOST="${registry_host}" \
  REGISTRY_USER="${registry_user}" \
  REGISTRY_PASSWORD="${registry_password}" \
    python - <<'PY' |
import base64
import json
import os


host = os.environ["REGISTRY_HOST"]
username = os.environ["REGISTRY_USER"]
password = os.environ["REGISTRY_PASSWORD"]
auths = {}

if username:
    auth = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")
    auths[host] = {
        "username": username,
        "password": password,
        "auth": auth,
    }

docker_config = json.dumps(
    {"auths": auths},
    separators=(",", ":"),
).encode("utf-8")

print(
    json.dumps(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": (
                    "blackduck-wintermute-"
                    "registry"
                ),
                "namespace": os.environ[
                    "NAMESPACE"
                ],
            },
            "type": (
                "kubernetes.io/"
                "dockerconfigjson"
            ),
            "data": {
                ".dockerconfigjson": (
                    base64.b64encode(
                        docker_config
                    ).decode("ascii")
                )
            },
        }
    )
)
PY
    k apply --filename -

  unset registry_password

  print "Credentials configured."
}

render() {
  require_command python
  require_command kubectl
  require_render_settings

  arguments=(
    "${root}/scripts/nonargo/render_jira_cronjob.py"
    --project-root "${root}"
    --output "${manifest}"
    --registry-host "${registry_host}"
    --registry-repository "${registry_repository}"
    --image-tag "${image_tag}"
    --namespace "${namespace}"
    --jira-url "${jira_url}"
    --jira-project-key "${jira_project_key}"
    --pipeline-mode "${pipeline_mode}"
    --max-create "${max_create}"
    --pvc-size "${pvc_size}"
    --workers "${workers}"
    --parent-workers "${parent_workers}"
    --rollup-workers "${rollup_workers}"
    --schedule "${schedule}"
    --timezone "${timezone}"
  )

  if [[ "${confirm_apply}" == "APPLY" ]]; then
    arguments+=(--confirm-apply)
  fi

  if [[ "${jira_insecure}" == "true" ]]; then
    arguments+=(--jira-insecure)
  fi

  if [[ "${enable_schedule}" == "true" ]]; then
    arguments+=(--enable-schedule)
  fi

  python "${arguments[@]}"
}

deploy() {
  require_context
  require_render_settings
  render

  k create namespace "${namespace}" \
    --dry-run=client \
    --output yaml |
    k apply --filename -

  for secret in \
    blackduck-wintermute-credentials \
    blackduck-wintermute-registry
  do
    k get secret "${secret}" \
      --namespace "${namespace}" >/dev/null ||
      fail "Missing Secret: ${secret}"
  done

  print "Reviewing Kubernetes diff"

  if k diff \
    --namespace "${namespace}" \
    --filename "${manifest}"
  then
    diff_result=0
  else
    diff_result=$?
  fi

  (( diff_result <= 1 )) ||
    fail "kubectl diff failed: ${diff_result}"

  k apply \
    --server-side \
    --field-manager \
    blackduck-wintermute \
    --filename "${manifest}"

  k get cronjob,pvc,configmap \
    --namespace "${namespace}"
}

run_job() {
  require_context

  k get cronjob \
    blackduck-jira-pipeline \
    --namespace "${namespace}" >/dev/null ||
    fail "Deploy the CronJob first"

  job="blackduck-jira-manual-$(date +%s)"

  k create job \
    --namespace "${namespace}" \
    --from=cronjob/blackduck-jira-pipeline \
    "${job}"

  print -r -- "${job}" \
    > "${latest_job_file}"

  print "Submitted job: ${job}"
}

latest_job() {
  [[ -s "${latest_job_file}" ]] ||
    fail "No saved manual Job"

  cat "${latest_job_file}"
}

show_logs() {
  require_context
  job="${1:-$(latest_job)}"

  k logs \
    --namespace "${namespace}" \
    "job/${job}" \
    --all-containers=true \
    --tail=500
}

status() {
  require_context
  job="${1:-$(latest_job)}"

  k get job,pods \
    --namespace "${namespace}" \
    -l "job-name=${job}" \
    -o wide
}

wait_job() {
  require_context
  job="${1:-$(latest_job)}"
  started="$(date +%s)"

  while true; do
    complete="$(
      k get job "${job}" \
        --namespace "${namespace}" \
        -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' \
        2>/dev/null || true
    )"
    failed="$(
      k get job "${job}" \
        --namespace "${namespace}" \
        -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' \
        2>/dev/null || true
    )"

    if [[ "${complete}" == "True" ]]; then
      show_logs "${job}"
      return 0
    fi

    if [[ "${failed}" == "True" ]]; then
      show_logs "${job}" || true
      k describe job "${job}" \
        --namespace "${namespace}"
      return 1
    fi

    current="$(date +%s)"

    if (( current - started >= wait_timeout )); then
      fail "Job timed out after ${wait_timeout}s"
    fi

    sleep 10
  done
}

all() {
  preflight
  build_push
  configure
  deploy
  run_job
  wait_job
}

command="${1:-help}"
shift || true

case "${command}" in
  preflight)
    preflight
    ;;
  build-push)
    build_push
    ;;
  configure)
    configure
    ;;
  render)
    render
    ;;
  deploy)
    deploy
    ;;
  run)
    run_job
    ;;
  wait)
    wait_job "$@"
    ;;
  status)
    status "$@"
    ;;
  logs)
    show_logs "$@"
    ;;
  all)
    all
    ;;
  *)
    cat <<'USAGE'
Usage: scripts/nonargo/no_argo_jira_k8s.zsh COMMAND

Commands:
  preflight   Check the selected cluster and permissions
  build-push  Build and push the all-in-one Jira image
  configure   Prompt for credentials and create Secrets
  render      Render a non-Argo suspended CronJob
  deploy      Render, diff, and apply the CronJob
  run         Start one manual Job from the CronJob
  wait        Wait for the latest manual Job
  status      Show the latest Job and Pod
  logs        Show logs for the latest Job
  all         Build, configure, deploy, run, and wait

Required non-secret environment:
  KUBE_CONTEXT
  REGISTRY_HOST
  REGISTRY_REPOSITORY
  JIRA_URL
  JIRA_PROJECT_KEY

Optional:
  IMAGE_TAG              Defaults to current Git commit
  KUBE_NAMESPACE         Default: blackduck-wintermute
  PVC_SIZE               Default: 10Gi
  PIPELINE_MODE           Default: dry-run
  CONFIRM_APPLY           Must equal APPLY for apply mode
  MAX_CREATE              Default: 10
  WORKERS                 Default: 2
  CRON_SCHEDULE           Default: 0 2 * * *
  CRON_TIMEZONE           Default: Etc/UTC
  ENABLE_SCHEDULE         Default: false
USAGE
    ;;
esac
