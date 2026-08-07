#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

root="${0:A:h:h}"

print "FULL APPLY WARNING"
print "=================="
print "This may create more than 3,600 Jira issues."
print "Datadog will use existing site-bound state and only send new events."
print

read -r "jira_confirm?Type JIRA PROJECT REVIEWED to continue: "

[[ "${jira_confirm}" == "JIRA PROJECT REVIEWED" ]] || {
  print "Cancelled."
  exit 1
}

print
print "Archiving local Jira state."
print "Existing Jira issues will still be found by deterministic labels."

/bin/zsh \
  "${root}/scripts/archive_local_jira_state.zsh"

print
print "Running a full destination dry run first."

/bin/zsh \
  "${root}/scripts/local_cohort_k8s.zsh" \
  submit \
  --wait \
  --jira-mode dry-run \
  --datadog-mode dry-run \
  --jira-max-create 5000 \
  --datadog-max-send 100

print
print "Review the dry-run counts above."
print "Expected current Jira scale is approximately 3,624 issues."
print

read -r "apply_confirm?Type APPLY FULL COHORT to continue: "

[[ "${apply_confirm}" == "APPLY FULL COHORT" ]] || {
  print "Cancelled after dry run."
  exit 1
}

exec /bin/zsh \
  "${root}/scripts/local_cohort_k8s.zsh" \
  submit \
  --wait \
  --jira-mode apply \
  --datadog-mode apply \
  --confirm-apply \
  --jira-max-create 5000 \
  --datadog-max-send 100
