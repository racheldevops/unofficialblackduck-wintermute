#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

namespace="${LOCAL_COHORT_NAMESPACE:-blackduck-wintermute-local}"
expected_context="${LOCAL_K8S_CONTEXT:-docker-desktop}"
pod="wintermute-vulnerability-list-$(date +%s)"
phase=""

cleanup() {
  kubectl delete pod "${pod}" \
    --namespace "${namespace}" \
    --ignore-not-found \
    --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

actual_context="$(kubectl config current-context)"

[[ "${actual_context}" == "${expected_context}" ]] || {
  print -u2 "Expected ${expected_context}, found ${actual_context}"
  exit 1
}

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
    - name: list
      image: blackduck-wintermute-source:local
      imagePullPolicy: Never
      command:
        - python
        - -c
      args:
        - |
          from collections import defaultdict
          from pathlib import Path

          from wintermute.blackduck.cohort import load_cohort

          root = Path("/cohorts")
          directories = sorted(
              (
                  path
                  for path in root.iterdir()
                  if path.is_dir()
                  and (path / "READY").is_file()
              ),
              key=lambda path: path.name,
              reverse=True,
          )

          if not directories:
              raise SystemExit("No ready cohorts found")

          cohort = load_cohort(directories[0])
          groups = defaultdict(
              lambda: {
                  "projects": set(),
                  "findings": 0,
              }
          )

          for finding in cohort.findings:
              vulnerability = (
                  finding.vulnerability
                  or "UNKNOWN"
              )
              groups[vulnerability]["findings"] += 1
              groups[vulnerability]["projects"].add(
                  (
                      finding.project_version.project,
                      finding.project_version.version,
                      finding.project_version.version_href,
                  )
              )

          rows = sorted(
              (
                  (
                      vulnerability,
                      len(values["projects"]),
                      values["findings"],
                  )
                  for vulnerability, values
                  in groups.items()
                  if vulnerability != "UNKNOWN"
              ),
              key=lambda row: (
                  row[1],
                  row[2],
                  row[0].lower(),
              ),
          )

          print(f"Latest cohort: {cohort.cohort_id}")
          print()
          print(
              "Exact vulnerability ID\t"
              "Affected project versions\t"
              "Direct findings\t"
              "Maximum new Jira issues"
          )

          for vulnerability, projects, findings in rows[:40]:
              print(
                  f"{vulnerability}\t"
                  f"{projects}\t"
                  f"{findings}\t"
                  f"{projects + 1}"
              )
      volumeMounts:
        - name: cohorts
          mountPath: /cohorts
          readOnly: true
  volumes:
    - name: cohorts
      persistentVolumeClaim:
        claimName: blackduck-wintermute-cohorts
YAML

for attempt in {1..120}; do
  phase="$(
    kubectl get pod "${pod}" \
      --namespace "${namespace}" \
      --output jsonpath='{.status.phase}' \
      2>/dev/null || true
  )"

  case "${phase}" in
    Succeeded|Failed)
      break
      ;;
  esac

  sleep 1
done

kubectl logs "${pod}" \
  --namespace "${namespace}" \
  --container list

[[ "${phase}" == "Succeeded" ]]
