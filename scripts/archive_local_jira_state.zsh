#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

namespace="${LOCAL_COHORT_NAMESPACE:-blackduck-wintermute-local}"
pod="wintermute-jira-state-archive-$(date +%s)"
started="$(date +%s)"

cleanup() {
  kubectl delete pod "${pod}" \
    --namespace "${namespace}" \
    --ignore-not-found \
    --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cat <<YAML | kubectl create --filename - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${pod}
  namespace: ${namespace}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
  containers:
    - name: archive
      image: blackduck-wintermute-jira:local
      imagePullPolicy: Never
      command:
        - /bin/sh
        - -c
      args:
        - |
          set -eu
          state=/data/state/jira-rollup-state.json

          if [ ! -f "\${state}" ]; then
            echo "No active Jira state found."
            exit 0
          fi

          stamp="\$(date -u +%Y%m%dT%H%M%SZ)"
          destination="/data/state/jira-rollup-state.before-full-apply-\${stamp}.json"
          mv "\${state}" "\${destination}"
          echo "Archived state: \${destination}"
      volumeMounts:
        - name: jira-data
          mountPath: /data
  volumes:
    - name: jira-data
      persistentVolumeClaim:
        claimName: blackduck-wintermute-jira-data
YAML

while true; do
  phase="$(
    kubectl get pod "${pod}" \
      --namespace "${namespace}" \
      --output jsonpath='{.status.phase}' \
      2>/dev/null || true
  )"

  case "${phase}" in
    Succeeded)
      kubectl logs "${pod}" \
        --namespace "${namespace}" \
        --container archive
      exit 0
      ;;
    Failed)
      kubectl logs "${pod}" \
        --namespace "${namespace}" \
        --all-containers=true || true
      exit 1
      ;;
  esac

  current="$(date +%s)"

  if (( current - started > 120 )); then
    print -u2 "Timed out archiving Jira state"
    exit 1
  fi

  sleep 2
done
