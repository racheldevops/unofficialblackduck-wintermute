#!/bin/zsh
emulate -L zsh
setopt PIPE_FAIL ERR_EXIT NO_UNSET

root="${0:A:h:h}"
namespace="${LOCAL_COHORT_NAMESPACE:-blackduck-wintermute-local}"
expected_context="${LOCAL_K8S_CONTEXT:-docker-desktop}"
argo_namespace="${LOCAL_ARGO_NAMESPACE:-argo}"
argo_version="${ARGO_VERSION:-v3.7.4}"
overlay="${root}/deploy/overlays/docker-desktop-cohort"
state_dir="${root}/.local-k8s"
latest_workflow_file="${state_dir}/latest-workflow.txt"

source_image="blackduck-wintermute-source:local"
jira_image="blackduck-wintermute-jira:local"
datadog_image="blackduck-wintermute-datadog:local"
scm_image="blackduck-wintermute-scm:local"

mkdir -p "${state_dir}"

fail() {
  print -u2 -- "ERROR: $*"
  return 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 ||
    fail "Required command not found: $1"
}

python_command() {
  local virtual_python

  virtual_python="${VIRTUAL_ENV:-}/bin/python"

  if [[
    -n "${VIRTUAL_ENV:-}"
    && -x "${virtual_python}"
  ]]; then
    print -r -- "${virtual_python}"
    return
  fi

  command -v python3 ||
    command -v python ||
    fail "Python was not found"
}

check_context() {
  require_command kubectl
  require_command docker

  local actual_context

  actual_context="$(
    kubectl config current-context 2>/dev/null
  )"

  [[ "${actual_context}" == "${expected_context}" ]] ||
    fail \
      "Expected Kubernetes context ${expected_context}, found ${actual_context}"

  kubectl cluster-info >/dev/null

  kubectl wait \
    --for=condition=Ready \
    nodes \
    --all \
    --timeout=120s >/dev/null
}

preflight() {
  check_context

  print "Context"
  print "======="
  kubectl config current-context

  print
  print "Nodes"
  print "====="
  kubectl get nodes -o wide

  print
  print "Allocatable resources"
  print "====================="

  kubectl get nodes \
    -o custom-columns=NAME:.metadata.name,CPU:.status.allocatable.cpu,MEMORY:.status.allocatable.memory

  print
  print "Storage classes"
  print "==============="
  kubectl get storageclass

  print
  print "Docker resources"
  print "================"

  docker info \
    --format 'CPUs={{.NCPU}} MemoryBytes={{.MemTotal}}'

  print
  print "Argo CRDs"
  print "=========="

  local crd

  for crd in \
    workflows.argoproj.io \
    workflowtemplates.argoproj.io \
    cronworkflows.argoproj.io
  do
    if kubectl get crd "${crd}" >/dev/null 2>&1; then
      print "FOUND ${crd}"
    else
      print "MISSING ${crd}"
    fi
  done
}

install_argo() {
  check_context

  kubectl create namespace "${argo_namespace}" \
    --dry-run=client \
    --output yaml |
  kubectl apply \
    --server-side \
    --field-manager blackduck-wintermute-local \
    --filename -

  local manifest_url

  manifest_url="$(
    printf '%s%s%s' \
      "https://github.com/argoproj/argo-workflows/" \
      "releases/download/${argo_version}/" \
      "quick-start-minimal.yaml"
  )"

  print "Installing pinned Argo Workflows ${argo_version}"

  kubectl apply \
    --server-side \
    --namespace "${argo_namespace}" \
    --filename "${manifest_url}"

  local crd

  for crd in \
    workflows.argoproj.io \
    workflowtemplates.argoproj.io \
    cronworkflows.argoproj.io
  do
    kubectl wait \
      --for=condition=Established \
      "crd/${crd}" \
      --timeout=180s
  done

  kubectl rollout status \
    deployment/workflow-controller \
    --namespace "${argo_namespace}" \
    --timeout=300s

  if kubectl get deployment argo-server \
    --namespace "${argo_namespace}" \
    >/dev/null 2>&1
  then
    kubectl rollout status \
      deployment/argo-server \
      --namespace "${argo_namespace}" \
      --timeout=300s
  fi
}

load_images() {
  local node_name="$1"
  local cluster_name
  shift

  local -a images
  images=("$@")
  cluster_name="${node_name%-control-plane}"

  if command -v kind >/dev/null 2>&1 &&
    kind get clusters 2>/dev/null |
      grep -Fx "${cluster_name}" >/dev/null
  then
    kind load docker-image \
      --name "${cluster_name}" \
      "${images[@]}"

    return
  fi

  if docker inspect "${node_name}" >/dev/null 2>&1; then
    local image

    for image in "${images[@]}"; do
      print "Loading ${image} into ${node_name}"

      docker save "${image}" |
      docker exec -i "${node_name}" \
        ctr --namespace k8s.io images import -
    done

    return
  fi

  fail "Cannot load local images into node ${node_name}"
}

build_images() {
  check_context

  local -a targets
  local -a images
  local index
  local node_name

  targets=(
    source
    jira
    datadog
    scm
  )
  images=(
    "${source_image}"
    "${jira_image}"
    "${datadog_image}"
    "${scm_image}"
  )

  for ((
    index = 1;
    index <= ${#targets};
    index++
  )); do
    print "Building ${images[index]}"

    docker build \
      --pull \
      --target "${targets[index]}" \
      --tag "${images[index]}" \
      "${root}"
  done

  node_name="$(
    kubectl get nodes \
      -o jsonpath='{.items[0].metadata.name}'
  )"

  load_images \
    "${node_name}" \
    "${images[@]}"
}

apply_local_secrets() {
  local require_scm="${1:-false}"
  local github_org="${GITHUB_ORG:-}"
  local github_token="${GITHUB_TOKEN:-}"
  local python_bin
  local -a helper_args

  if [[
    -z "${BLACKDUCK_URL:-}"
    || -z "${BLACKDUCK_API_TOKEN:-}"
  ]]; then
    source "${root}/scripts/load_blackduck_env.zsh" ||
      fail "Unable to load Black Duck credentials"
  fi

  [[ -n "${BLACKDUCK_URL:-}" ]] ||
    fail "BLACKDUCK_URL is empty"

  [[ -n "${BLACKDUCK_API_TOKEN:-}" ]] ||
    fail "BLACKDUCK_API_TOKEN is empty"

  if [[ "${require_scm}" == "true" ]]; then
    if [[ -z "${github_org}" ]]; then
      read -r "github_org?GitHub organization: "
    fi

    if [[ -z "${github_token}" ]]; then
      read -r -s \
        "github_token?GitHub read-only token: "
      print
    fi

    [[ -n "${github_org}" ]] ||
      fail "GitHub organization is required"

    [[ -n "${github_token}" ]] ||
      fail "GitHub token is required"
  elif [[
    -n "${github_org}"
    && -z "${github_token}"
  ]]; then
    fail \
      "GITHUB_ORG is set but GITHUB_TOKEN is missing"
  elif [[
    -z "${github_org}"
    && -n "${github_token}"
  ]]; then
    fail \
      "GITHUB_TOKEN is set but GITHUB_ORG is missing"
  fi

  python_bin="$(python_command)"

  helper_args=(
    apply-secrets
    --namespace
    "${namespace}"
  )

  if [[ "${require_scm}" == "true" ]]; then
    helper_args+=(--require-scm)
  fi

  NAMESPACE="${namespace}" \
  BLACKDUCK_URL="${BLACKDUCK_URL}" \
  BLACKDUCK_API_TOKEN="${BLACKDUCK_API_TOKEN}" \
  GITHUB_ORG="${github_org}" \
  GITHUB_TOKEN="${github_token}" \
  GITHUB_GRAPHQL_URL="${GITHUB_GRAPHQL_URL:-}" \
  GITHUB_REST_URL="${GITHUB_REST_URL:-}" \
    "${python_bin}" \
      "${root}/scripts/local_cohort_k8s_helper.py" \
      "${helper_args[@]}"
}

deploy() {
  check_context

  local crd
  local suspended

  for crd in \
    workflows.argoproj.io \
    workflowtemplates.argoproj.io \
    cronworkflows.argoproj.io
  do
    kubectl get crd "${crd}" >/dev/null ||
      fail "Missing Argo CRD: ${crd}"
  done

  kubectl apply \
    --server-side \
    --field-manager blackduck-wintermute-local \
    --filename "${overlay}/namespace.yaml"

  apply_local_secrets false

  kubectl kustomize "${overlay}" \
    > "${state_dir}/rendered-local-cohort.yaml"

  kubectl apply \
    --server-side \
    --field-manager blackduck-wintermute-local \
    --filename "${state_dir}/rendered-local-cohort.yaml"

  kubectl get \
    workflowtemplate,cronworkflow,pvc \
    --namespace "${namespace}"

  suspended="$(
    kubectl get cronworkflow \
      blackduck-wintermute-cohort \
      --namespace "${namespace}" \
      -o jsonpath='{.spec.suspend}'
  )"

  [[ "${suspended}" == "true" ]] ||
    fail "Local CronWorkflow is not suspended"
}

workflow_name() {
  if [[ -s "${latest_workflow_file}" ]]; then
    cat "${latest_workflow_file}"
    return
  fi

  kubectl get workflows \
    --namespace "${namespace}" \
    --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{.items[-1:].metadata.name}'
}

show_logs() {
  local workflow="$1"
  local pod_resources
  local pod_resource

  pod_resources="$(
    kubectl get pods \
      --namespace "${namespace}" \
      --selector \
      "workflows.argoproj.io/workflow=${workflow}" \
      --sort-by=.metadata.creationTimestamp \
      -o name
  )"

  if [[ -z "${pod_resources}" ]]; then
    print "No Pods found for workflow ${workflow}"
    return
  fi

  while IFS= read -r pod_resource; do
    [[ -n "${pod_resource}" ]] || continue

    print
    print "===== ${pod_resource} ====="

    kubectl logs \
      --namespace "${namespace}" \
      "${pod_resource}" \
      --all-containers=true \
      --prefix=true || true
  done <<< "${pod_resources}"
}

watch_workflow() {
  local workflow="$1"
  local timeout_seconds="${LOCAL_WORKFLOW_TIMEOUT_SECONDS:-7200}"
  local started
  local previous_phase=""
  local phase
  local current_epoch

  started="$(date +%s)"

  while true; do
    phase="$(
      kubectl get workflow "${workflow}" \
        --namespace "${namespace}" \
        -o jsonpath='{.status.phase}' \
        2>/dev/null || true
    )"

    if [[ "${phase}" != "${previous_phase}" ]]; then
      print \
        "Workflow ${workflow}: ${phase:-Pending}"

      kubectl get pods \
        --namespace "${namespace}" \
        --selector \
        "workflows.argoproj.io/workflow=${workflow}" \
        -o wide || true

      previous_phase="${phase}"
    fi

    case "${phase}" in
      Succeeded)
        show_logs "${workflow}"
        return 0
        ;;
      Failed|Error)
        show_logs "${workflow}"

        kubectl get workflow "${workflow}" \
          --namespace "${namespace}" \
          -o yaml \
          > "${state_dir}/${workflow}-failed.yaml"

        return 1
        ;;
    esac

    current_epoch="$(date +%s)"

    if ((
      current_epoch - started
      >= timeout_seconds
    )); then
      print -u2 \
        "Workflow timed out after ${timeout_seconds}s"

      return 1
    fi

    sleep 10
  done
}

submit() {
  check_context

  local wait_for_completion="false"
  local confirm_apply="false"
  local jira_mode="${LOCAL_JIRA_MODE:-dry-run}"
  local datadog_mode="${LOCAL_DATADOG_MODE:-dry-run}"
  local scm_mode="${LOCAL_SCM_MODE:-disabled}"
  local jira_only_vulnerability=""
  local jira_max_create="${LOCAL_JIRA_MAX_CREATE:-5000}"
  local datadog_max_send="${LOCAL_DATADOG_MAX_SEND:-100}"

  while (( $# > 0 )); do
    case "$1" in
      --wait)
        wait_for_completion="true"
        shift
        ;;
      --confirm-apply)
        confirm_apply="true"
        shift
        ;;
      --jira-mode)
        jira_mode="$2"
        shift 2
        ;;
      --datadog-mode)
        datadog_mode="$2"
        shift 2
        ;;
      --scm-mode)
        scm_mode="$2"
        shift 2
        ;;
      --jira-only-vulnerability)
        jira_only_vulnerability="$2"
        shift 2
        ;;
      --jira-max-create)
        jira_max_create="$2"
        shift 2
        ;;
      --datadog-max-send)
        datadog_max_send="$2"
        shift 2
        ;;
      *)
        fail "Unknown submit option: $1"
        ;;
    esac
  done

  kubectl get workflowtemplate \
    blackduck-wintermute-cohort \
    --namespace "${namespace}" >/dev/null ||
    fail "Deploy local cohort resources first"

  if [[ "${scm_mode}" == "read-only" ]]; then
    apply_local_secrets true
  fi

  local python_bin
  local workflow_resource
  local workflow
  local -a helper_args

  python_bin="$(python_command)"

  helper_args=(
    submit
    --namespace "${namespace}"
    --source-image "${source_image}"
    --jira-image "${jira_image}"
    --datadog-image "${datadog_image}"
    --scm-image "${scm_image}"
    --jira-mode "${jira_mode}"
    --datadog-mode "${datadog_mode}"
    --scm-mode "${scm_mode}"
    --jira-only-vulnerability \
      "${jira_only_vulnerability}"
    --jira-max-create "${jira_max_create}"
    --datadog-max-send "${datadog_max_send}"
    --retain-cohorts 3
  )

  if [[ "${confirm_apply}" == "true" ]]; then
    helper_args+=(--confirm-apply)
  fi

  workflow_resource="$(
    "${python_bin}" \
      "${root}/scripts/local_cohort_k8s_helper.py" \
      "${helper_args[@]}"
  )"
  workflow="${workflow_resource#*/}"

  printf '%s\n' "${workflow}" \
    > "${latest_workflow_file}"

  print "Submitted ${workflow}"
  print "Jira mode: ${jira_mode}"
  print "Datadog mode: ${datadog_mode}"
  print "SCM mode: ${scm_mode}"

  if [[ -n "${jira_only_vulnerability}" ]]; then
    print \
      "Jira vulnerability: ${jira_only_vulnerability}"
  fi

  if [[ "${wait_for_completion}" == "true" ]]; then
    watch_workflow "${workflow}"
  fi
}

status_workflow() {
  check_context

  local workflow

  workflow="$(workflow_name)"

  [[ -n "${workflow}" ]] ||
    fail "No local workflow has been submitted"

  kubectl get workflow "${workflow}" \
    --namespace "${namespace}" \
    -o wide

  kubectl get pods \
    --namespace "${namespace}" \
    --selector \
    "workflows.argoproj.io/workflow=${workflow}" \
    -o wide
}

logs_workflow() {
  check_context

  local workflow

  workflow="$(workflow_name)"

  [[ -n "${workflow}" ]] ||
    fail "No local workflow has been submitted"

  show_logs "${workflow}"
}

diagnose() {
  check_context

  local workflow

  workflow="$(workflow_name)"

  [[ -n "${workflow}" ]] ||
    fail "No local workflow has been submitted"

  kubectl get workflow "${workflow}" \
    --namespace "${namespace}" \
    -o yaml \
    > "${state_dir}/${workflow}-diagnostic.yaml"

  kubectl describe workflow "${workflow}" \
    --namespace "${namespace}"

  show_logs "${workflow}"
}

all() {
  preflight
  install_argo
  build_images
  deploy
  submit --wait "$@"
}

command="${1:-help}"
shift || true

case "${command}" in
  preflight)
    preflight
    ;;
  install-argo)
    install_argo
    ;;
  build)
    build_images
    ;;
  deploy)
    deploy
    ;;
  submit)
    submit "$@"
    ;;
  wait)
    check_context
    workflow="$(workflow_name)"

    [[ -n "${workflow}" ]] ||
      fail "No local workflow has been submitted"

    watch_workflow "${workflow}"
    ;;
  status)
    status_workflow
    ;;
  diagnose)
    diagnose
    ;;
  logs)
    logs_workflow
    ;;
  all)
    all "$@"
    ;;
  *)
    cat <<'USAGE'
Usage: scripts/local_cohort_k8s.zsh COMMAND

Commands:
  preflight
  install-argo
  build
  deploy
  submit
  submit --wait
  submit --wait --scm-mode read-only
  submit --wait --datadog-mode disabled --scm-mode read-only
  wait
  status
  logs
  diagnose
  all

SCM environment:
  GITHUB_ORG
  GITHUB_TOKEN
  GITHUB_GRAPHQL_URL   optional
  GITHUB_REST_URL      optional
USAGE
    ;;
esac
