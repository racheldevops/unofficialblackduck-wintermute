#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

namespace="${LOCAL_COHORT_NAMESPACE:-blackduck-wintermute-local}"
expected_context="${LOCAL_K8S_CONTEXT:-docker-desktop}"
pod="wintermute-datadog-state-archive-$(date +%s)"
timeout_seconds=120
started="$(date +%s)"

cleanup() {
  kubectl delete pod "${pod}" \
    --namespace "${namespace}" \
    --ignore-not-found \
    --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

actual_context="$(kubectl config current-context)"

[[ "${actual_context}" == "${expected_context}" ]] || {
  print -u2 "Expected context ${expected_context}, found ${actual_context}"
  exit 1
}

kubectl delete pod \
  wintermute-datadog-reset-1786103826 \
  --namespace "${namespace}" \
  --ignore-not-found \
  --wait=false >/dev/null 2>&1 || true

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
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: archive
      image: blackduck-wintermute-datadog:local
      imagePullPolicy: Never
      command:
        - python
        - -c
      args:
        - |
          from datetime import datetime, timezone
          from pathlib import Path

          path = Path(
              "/data/state/datadog-findings-state.json"
          )

          if not path.exists():
              print("No active Datadog state found.")
          else:
              stamp = datetime.now(
                  timezone.utc
              ).strftime("%Y%m%dT%H%M%SZ")
              destination = path.with_name(
                  f"{path.stem}.before-verified-eu-"
                  f"{stamp}{path.suffix}"
              )
              path.rename(destination)
              print(f"Archived state: {destination}")
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: datadog-data
          mountPath: /data
  volumes:
    - name: datadog-data
      persistentVolumeClaim:
        claimName: blackduck-wintermute-datadog-data
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
      kubectl describe pod "${pod}" \
        --namespace "${namespace}" |
        tail -80
      exit 1
      ;;
  esac

  current="$(date +%s)"

  if (( current - started >= timeout_seconds )); then
    print -u2 "Timed out; current Pod phase: ${phase:-Unknown}"
    kubectl describe pod "${pod}" \
      --namespace "${namespace}" |
      tail -80
    exit 1
  fi

  sleep 2
done
