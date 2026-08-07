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

mkdir -p "${state_dir}"

fail() {
  print -u2 -- "ERROR: $*"
  return 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 ||
    fail "Required command not found: $1"
}

check_context() {
  require_command kubectl
  require_command docker

  actual_context="$(kubectl config current-context 2>/dev/null)"

  [[ "${actual_context}" == "${expected_context}" ]] ||
    fail "Expected Kubernetes context ${expected_context}, found ${actual_context}"

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
    -o yaml |
    kubectl apply -f -

  manifest_url="https://github.com/argoproj/argo-workflows/releases/download/${argo_version}/quick-start-minimal.yaml"

  print "Installing pinned Argo Workflows ${argo_version}"
  kubectl apply \
    --server-side \
    --namespace "${argo_namespace}" \
    --filename "${manifest_url}"

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
    --namespace "${argo_namespace}" >/dev/null 2>&1
  then
    kubectl rollout status \
      deployment/argo-server \
      --namespace "${argo_namespace}" \
      --timeout=300s
  fi
}

build_images() {
  check_context

  docker build \
    --target source \
    --tag "${source_image}" \
    "${root}"

  docker build \
    --target jira \
    --tag "${jira_image}" \
    "${root}"

  docker build \
    --target datadog \
    --tag "${datadog_image}" \
    "${root}"

  node_name="$(
    kubectl get nodes \
      -o jsonpath='{.items[0].metadata.name}'
  )"
  cluster_name="${node_name%-control-plane}"
  images=(
    "${source_image}"
    "${jira_image}"
    "${datadog_image}"
  )

  if command -v kind >/dev/null 2>&1 &&
    kind get clusters 2>/dev/null |
      grep -Fx "${cluster_name}" >/dev/null
  then
    kind load docker-image \
      --name "${cluster_name}" \
      "${images[@]}"
  elif docker inspect "${node_name}" >/dev/null 2>&1
  then
    for image in "${images[@]}"; do
      print "Loading ${image} into ${node_name}"
      docker save "${image}" |
        docker exec -i "${node_name}" \
          ctr --namespace k8s.io images import -
    done
  else
    fail "Cannot load local images into kind node ${node_name}; install the kind CLI or verify Docker Desktop image sharing"
  fi
}

apply_local_secrets() {
  source "${root}/scripts/load_blackduck_env.zsh" ||
    fail "Unable to load Black Duck credentials from macOS Keychain"

  [[ -n "${BLACKDUCK_URL:-}" ]] ||
    fail "BLACKDUCK_URL is empty"

  [[ -n "${BLACKDUCK_API_TOKEN:-}" ]] ||
    fail "BLACKDUCK_API_TOKEN is empty"

  NAMESPACE="${namespace}" \
  BLACKDUCK_URL="${BLACKDUCK_URL}" \
  BLACKDUCK_API_TOKEN="${BLACKDUCK_API_TOKEN}" \
    python - <<'PY' |
import base64
import json
import os

namespace = os.environ["NAMESPACE"]

def encoded(value):
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("ascii")

items = [
    {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "blackduck-wintermute-blackduck-credentials",
            "namespace": namespace,
        },
        "type": "Opaque",
        "data": {
            "BLACKDUCK_URL": encoded(
                os.environ["BLACKDUCK_URL"]
            ),
            "BLACKDUCK_API_TOKEN": encoded(
                os.environ["BLACKDUCK_API_TOKEN"]
            ),
        },
    },
    {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "blackduck-wintermute-jira-credentials",
            "namespace": namespace,
        },
        "type": "Opaque",
        "data": {},
    },
    {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "blackduck-wintermute-datadog-credentials",
            "namespace": namespace,
        },
        "type": "Opaque",
        "data": {},
    },
    {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "blackduck-wintermute-registry",
            "namespace": namespace,
        },
        "type": "kubernetes.io/dockerconfigjson",
        "data": {
            ".dockerconfigjson": encoded(
                '{"auths":{}}'
            ),
        },
    },
]

print(
    json.dumps(
        {
            "apiVersion": "v1",
            "kind": "List",
            "items": items,
        }
    )
)
PY
  kubectl apply -f -
}

deploy() {
  check_context

  for crd in \
    workflows.argoproj.io \
    workflowtemplates.argoproj.io \
    cronworkflows.argoproj.io
  do
    kubectl get crd "${crd}" >/dev/null ||
      fail "Missing Argo CRD: ${crd}"
  done

  kubectl apply \
    --filename "${overlay}/namespace.yaml"

  apply_local_secrets

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
  workflow="$1"
  pod_resources="$(
    kubectl get pods       --namespace "${namespace}"       --selector "workflows.argoproj.io/workflow=${workflow}"       --sort-by=.metadata.creationTimestamp       -o name
  )"

  if [[ -z "${pod_resources}" ]]; then
    print "No Pods found for workflow ${workflow}"
    return 0
  fi

  while IFS= read -r pod_resource; do
    [[ -n "${pod_resource}" ]] || continue
    print
    print "===== ${pod_resource} ====="

    kubectl logs       --namespace "${namespace}"       "${pod_resource}"       --all-containers=true       --prefix=true || true
  done <<< "${pod_resources}"
}

diagnose() {
  check_context
  workflow="$(workflow_name)"

  [[ -n "${workflow}" ]] ||
    fail "No local workflow has been submitted"

  print "Workflow"
  print "========"
  kubectl get workflow "${workflow}"     --namespace "${namespace}"     -o wide

  print
  print "Workflow nodes"
  print "=============="
  kubectl get workflow "${workflow}" \
    --namespace "${namespace}" \
    -o json |
    python -c '
import json
import sys

payload = json.load(sys.stdin)
nodes = payload.get("status", {}).get("nodes", {})

for node in sorted(
    nodes.values(),
    key=lambda item: (
        item.get("startedAt", ""),
        item.get("displayName", ""),
    ),
):
    print(
        "{}\t{}\t{}".format(
            node.get("displayName", ""),
            node.get("phase", ""),
            node.get("message", ""),
        )
    )
'

  print
  print "Pods"
  print "===="
  kubectl get pods     --namespace "${namespace}"     --selector "workflows.argoproj.io/workflow=${workflow}"     -o wide

  print
  print "Pod events"
  print "=========="
  pod_resources="$(
    kubectl get pods       --namespace "${namespace}"       --selector "workflows.argoproj.io/workflow=${workflow}"       -o name
  )"

  while IFS= read -r pod_resource; do
    [[ -n "${pod_resource}" ]] || continue
    kubectl describe       --namespace "${namespace}"       "${pod_resource}"
  done <<< "${pod_resources}"

  print
  print "Logs"
  print "===="
  show_logs "${workflow}"

  kubectl get workflow "${workflow}"     --namespace "${namespace}"     -o yaml     > "${state_dir}/${workflow}-diagnostic.yaml"
}

watch_workflow() {
  workflow="$1"
  timeout_seconds="${LOCAL_WORKFLOW_TIMEOUT_SECONDS:-3600}"
  started="$(date +%s)"
  previous_phase=""

  while true; do
    phase="$(
      kubectl get workflow "${workflow}" \
        --namespace "${namespace}" \
        -o jsonpath='{.status.phase}' \
        2>/dev/null || true
    )"

    if [[ "${phase}" != "${previous_phase}" ]]; then
      print "Workflow ${workflow}: ${phase:-Pending}"
      kubectl get pods \
        --namespace "${namespace}" \
        --selector "workflows.argoproj.io/workflow=${workflow}" \
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
    if (( current_epoch - started >= timeout_seconds )); then
      print -u2 "Workflow timed out after ${timeout_seconds}s"
      return 1
    fi

    sleep 10
  done
}

submit() {
  check_context

  kubectl get workflowtemplate \
    blackduck-wintermute-cohort \
    --namespace "${namespace}" >/dev/null ||
    fail "Deploy the local cohort resources first"

  workflow_resource="$(
    cat <<YAML |
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: blackduck-wintermute-local-
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: blackduck-wintermute
    app.kubernetes.io/component: local-cohort-smoke
spec:
  workflowTemplateRef:
    name: blackduck-wintermute-cohort
  arguments:
    parameters:
      - name: source-image
        value: ${source_image}
      - name: jira-image
        value: ${jira_image}
      - name: datadog-image
        value: ${datadog_image}
      - name: jira-mode
        value: dry-run
      - name: datadog-mode
        value: dry-run
      - name: confirm-apply
        value: "false"
      - name: retain-cohorts
        value: "3"
YAML
    kubectl create \
      --filename - \
      --output name
  )"

  workflow="${workflow_resource#*/}"
  printf '%s\n' "${workflow}" \
    > "${latest_workflow_file}"

  print "Submitted ${workflow}"

  if [[ "${1:-}" == "--wait" ]]; then
    watch_workflow "${workflow}"
  fi
}

status() {
  check_context
  workflow="$(workflow_name)"

  [[ -n "${workflow}" ]] ||
    fail "No local workflow has been submitted"

  kubectl get workflow "${workflow}" \
    --namespace "${namespace}" \
    -o wide

  kubectl get pods \
    --namespace "${namespace}" \
    --selector "workflows.argoproj.io/workflow=${workflow}" \
    -o wide
}

logs() {
  check_context
  workflow="$(workflow_name)"

  [[ -n "${workflow}" ]] ||
    fail "No local workflow has been submitted"

  show_logs "${workflow}"
}

all() {
  preflight
  install_argo
  build_images
  deploy
  submit --wait
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

    kubectl get workflow "${workflow}"       --namespace "${namespace}" >/dev/null ||
      fail "Workflow does not exist: ${workflow}"

    watch_workflow "${workflow}"
    ;;
  status)
    status
    ;;
  diagnose)
    diagnose
    ;;
  logs)
    logs
    ;;
  all)
    all
    ;;
  *)
    cat <<'USAGE'
Usage: scripts/local_cohort_k8s.zsh COMMAND

Commands:
  preflight      Validate Docker Desktop Kubernetes
  install-argo   Install pinned Argo Workflows
  build          Build and load the three local images
  deploy         Create scoped Secrets and apply suspended resources
  submit         Submit one manual dry-run workflow
  submit --wait  Submit and wait with logs
  wait           Wait for the latest submitted workflow
  status         Show the latest workflow and Pods
  logs           Show logs for the latest workflow
  diagnose       Diagnose the latest workflow
  all            Run preflight through submit --wait
USAGE
    ;;
esac
