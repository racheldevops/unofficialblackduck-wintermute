#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

root="${0:A:h:h}"
namespace="${LOCAL_COHORT_NAMESPACE:-blackduck-wintermute-local}"
expected_context="${LOCAL_K8S_CONTEXT:-docker-desktop}"
config_source="${root}/deploy/cohort/jira-rollup-config.json"
config_output="${root}/.local-k8s/jira-rollup-config.apply.json"

actual_context="$(kubectl config current-context)"

[[ "${actual_context}" == "${expected_context}" ]] || {
  print -u2 "Expected ${expected_context}, found ${actual_context}"
  exit 1
}

read -r "jira_url?Jira URL: "
read -r "jira_project_key?Jira project key: "
read -r "jira_user?Jira user: "
read -r -s "jira_token?Jira API token: "
print

read -r "jira_verify_tls_answer?Disable Jira TLS verification? [y/N]: "

case "${jira_verify_tls_answer:l}" in
  y|yes)
    jira_verify_tls="false"
    ;;
  *)
    jira_verify_tls="true"
    ;;
esac
read -r -s "datadog_key?Datadog API key: "
print

default_datadog_site="${LOCAL_DATADOG_SITE:-datadoghq.com}"
read -r "datadog_site?Datadog site [${default_datadog_site}]: "
datadog_site="${datadog_site:-${default_datadog_site}}"

read -r "datadog_insecure_answer?Disable Datadog TLS verification? [y/N]: "

case "${datadog_insecure_answer:l}" in
  y|yes)
    datadog_insecure="true"
    ;;
  *)
    datadog_insecure="false"
    ;;
esac

[[ -n "${jira_url}" ]] ||
  { print -u2 "Jira URL is required"; exit 1; }
[[ -n "${jira_project_key}" ]] ||
  { print -u2 "Jira project key is required"; exit 1; }
[[ -n "${jira_user}" ]] ||
  { print -u2 "Jira user is required"; exit 1; }
[[ -n "${jira_token}" ]] ||
  { print -u2 "Jira API token is required"; exit 1; }
[[ -n "${datadog_key}" ]] ||
  { print -u2 "Datadog API key is required"; exit 1; }

mkdir -p "${root}/.local-k8s"

CONFIG_SOURCE="${config_source}" \
CONFIG_OUTPUT="${config_output}" \
JIRA_URL="${jira_url%/}" \
JIRA_PROJECT_KEY="${jira_project_key}" \
JIRA_VERIFY_TLS="${jira_verify_tls}" \
  python - <<'PY'
import json
import os
from pathlib import Path

source = Path(os.environ["CONFIG_SOURCE"])
output = Path(os.environ["CONFIG_OUTPUT"])
payload = json.loads(
    source.read_text(encoding="utf-8")
)
jira = payload.setdefault("jira", {})
jira["url"] = os.environ["JIRA_URL"]
jira["project_key"] = os.environ[
    "JIRA_PROJECT_KEY"
]
jira["auth_mode"] = "basic"
jira["verify_tls"] = (
    os.environ["JIRA_VERIFY_TLS"]
    .strip()
    .lower()
    == "true"
)

output.write_text(
    json.dumps(payload, indent=2) + "\n",
    encoding="utf-8",
)
PY

kubectl create configmap \
  blackduck-wintermute-cohort-jira-config \
  --namespace "${namespace}" \
  --from-file="jira-rollup-config.json=${config_output}" \
  --dry-run=client \
  --output yaml |
kubectl apply -f -

NAMESPACE="${namespace}" \
JIRA_URL="${jira_url%/}" \
JIRA_USER="${jira_user}" \
JIRA_API_TOKEN="${jira_token}" \
DATADOG_API_KEY="${datadog_key}" \
DATADOG_SITE="${datadog_site}" \
DATADOG_INSECURE="${datadog_insecure}" \
  python - <<'PY' |
import base64
import json
import os

def encoded(value):
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("ascii")

namespace = os.environ["NAMESPACE"]

print(
    json.dumps(
        {
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": (
                            "blackduck-wintermute-"
                            "jira-credentials"
                        ),
                        "namespace": namespace,
                    },
                    "type": "Opaque",
                    "data": {
                        "JIRA_URL": encoded(
                            os.environ["JIRA_URL"]
                        ),
                        "JIRA_USER": encoded(
                            os.environ["JIRA_USER"]
                        ),
                        "JIRA_API_TOKEN": encoded(
                            os.environ[
                                "JIRA_API_TOKEN"
                            ]
                        ),
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": (
                            "blackduck-wintermute-"
                            "datadog-credentials"
                        ),
                        "namespace": namespace,
                    },
                    "type": "Opaque",
                    "data": {
                        "DATADOG_API_KEY": encoded(
                            os.environ[
                                "DATADOG_API_KEY"
                            ]
                        ),
                        "DATADOG_SITE": encoded(
                            os.environ[
                                "DATADOG_SITE"
                            ]
                        ),
                        "DATADOG_INSECURE": encoded(
                            os.environ[
                                "DATADOG_INSECURE"
                            ]
                        ),
                    },
                },
            ],
        }
    )
)
PY
kubectl apply -f -

unset jira_token datadog_key

print "Destination credentials and Jira config applied."
