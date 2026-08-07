#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET

root="${0:A:h:h}"

print "This will create Jira issues and send Datadog events."
print "Jira will be limited to one vulnerability."
print "Datadog will be limited to ten events."
print

"${root}/scripts/list_local_cohort_vulnerabilities.zsh"
print
read -r "vulnerability?Exact Jira vulnerability ID: "

[[ "${vulnerability}" =~ '^[A-Za-z0-9._:-]+$' ]] || {
  print -u2 "Invalid vulnerability ID"
  exit 1
}

read -r "confirmation?Type APPLY to continue: "

[[ "${confirmation}" == "APPLY" ]] || {
  print "Cancelled."
  exit 1
}

exec /bin/zsh "${root}/scripts/local_cohort_k8s.zsh" \
  submit \
  --wait \
  --jira-mode apply \
  --datadog-mode apply \
  --confirm-apply \
  --jira-only-vulnerability "${vulnerability}" \
  --jira-max-create 100 \
  --datadog-max-send 10
