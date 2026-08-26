#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

root="${0:A:h:h}"
context="${LOCAL_K8S_CONTEXT:-docker-desktop}"
namespace="${LOCAL_SCM_NAMESPACE:-blackduck-wintermute-scm-local}"
image="${LOCAL_SCM_IMAGE:-blackduck-wintermute-scm:local}"
storage="${LOCAL_SCM_STORAGE:-5Gi}"
state_dir="${root}/.local-k8s"
manifest="${state_dir}/scm-overview-local.yaml"
timeout="${LOCAL_SCM_TIMEOUT:-7200s}"

fail() {
  print -u2 -- "ERROR: $*"
  return 1
}

for command in docker kubectl python; do
  command -v "${command}" >/dev/null 2>&1 ||
    fail "Required command not found: ${command}"
done

actual_context="$(
  kubectl config current-context
)"

[[ "${actual_context}" == "${context}" ]] ||
  fail "Expected context ${context}, found ${actual_context}"

kubectl cluster-info >/dev/null

if [[ \
  -z "${BLACKDUCK_URL:-}" ||
  -z "${BLACKDUCK_API_TOKEN:-}" \
]]; then
  source "${root}/scripts/load_blackduck_env.zsh" ||
    fail "Black Duck credentials are unavailable"
fi

github_org="${GITHUB_ORG:-}"
github_token="${GITHUB_TOKEN:-}"

if [[ -z "${github_org}" ]]; then
  read -r "github_org?GitHub organization: "
fi

if [[ -z "${github_token}" ]]; then
  read -r -s "github_token?GitHub read-only token: "
  print
fi

[[ -n "${github_org}" ]] ||
  fail "GitHub organization is required"

[[ -n "${github_token}" ]] ||
  fail "GitHub token is required"

mkdir -p "${state_dir}"

print "Building ${image}"
docker build \
  --pull \
  --target scm \
  --tag "${image}" \
  "${root}"

node_name="$(
  kubectl get nodes \
    -o jsonpath='{.items[0].metadata.name}'
)"

docker inspect "${node_name}" >/dev/null 2>&1 ||
  fail "Kubernetes node is not visible as Docker container: ${node_name}"

print "Loading ${image} into ${node_name}"
docker save "${image}" |
  docker exec -i "${node_name}" \
    ctr --namespace k8s.io images import -

kubectl create namespace "${namespace}" \
  --dry-run=client \
  --output yaml |
kubectl apply --filename -

NAMESPACE="${namespace}" \
GITHUB_ORG="${github_org}" \
GITHUB_TOKEN="${github_token}" \
BLACKDUCK_URL="${BLACKDUCK_URL}" \
BLACKDUCK_API_TOKEN="${BLACKDUCK_API_TOKEN}" \
  python - <<'PY' |
import base64
import json
import os


def encoded(value: str) -> str:
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("ascii")


names = (
    "GITHUB_ORG",
    "GITHUB_TOKEN",
    "BLACKDUCK_URL",
    "BLACKDUCK_API_TOKEN",
)

print(
    json.dumps(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": (
                    "blackduck-wintermute-"
                    "scm-credentials"
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
                for name in names
            },
        }
    )
)
PY
kubectl apply --filename -

cat > "${manifest}" <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: blackduck-wintermute-scm-data
  namespace: ${namespace}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: ${storage}
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: blackduck-wintermute-scm-overview
  namespace: ${namespace}
spec:
  schedule: "0 2 * * *"
  suspend: true
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 2
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 0
      activeDeadlineSeconds: 7200
      template:
        spec:
          restartPolicy: Never
          automountServiceAccountToken: false
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            runAsGroup: 10001
            fsGroup: 10001
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: scm-overview
              image: ${image}
              imagePullPolicy: Never
              command:
                - blackduck-wintermute-scm-overview
              args:
                - --output-root
                - /data
                - --workers
                - "8"
                - --evidence-workers
                - "4"
                - --freshness-sla-days
                - "30"
                - --insecure
                - --allow-partial
              env:
                - name: TMPDIR
                  value: /tmp
              envFrom:
                - secretRef:
                    name: blackduck-wintermute-scm-credentials
              resources:
                requests:
                  cpu: 500m
                  memory: 512Mi
                limits:
                  cpu: "2"
                  memory: 2Gi
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities:
                  drop:
                    - ALL
              volumeMounts:
                - name: data
                  mountPath: /data
                - name: tmp
                  mountPath: /tmp
          volumes:
            - name: data
              persistentVolumeClaim:
                claimName: blackduck-wintermute-scm-data
            - name: tmp
              emptyDir:
                sizeLimit: 512Mi
YAML

kubectl apply --filename "${manifest}"

job="blackduck-wintermute-scm-manual-$(date +%s)"

kubectl create job \
  --namespace "${namespace}" \
  --from=cronjob/blackduck-wintermute-scm-overview \
  "${job}"

print "Submitted ${job}"

if kubectl wait \
  --namespace "${namespace}" \
  --for=condition=complete \
  "job/${job}" \
  --timeout="${timeout}"
then
  kubectl logs \
    --namespace "${namespace}" \
    "job/${job}" \
    --all-containers=true \
    --tail=500

  print
  print "SCM_KUBERNETES_OVERVIEW_OK"
  print "Namespace: ${namespace}"
  print "Job: ${job}"
else
  kubectl logs \
    --namespace "${namespace}" \
    "job/${job}" \
    --all-containers=true \
    --tail=500 || true

  kubectl describe \
    --namespace "${namespace}" \
    "job/${job}" || true

  exit 1
fi
