#!/bin/zsh

_wintermute_load_blackduck_env() {
  if [[ -n "${BLACKDUCK_URL:-}" && -n "${BLACKDUCK_API_TOKEN:-}" ]]; then
    return 0
  fi

  command -v security >/dev/null 2>&1 || return 1

  if [[ -z "${BLACKDUCK_URL:-}" ]]; then
    BLACKDUCK_URL="$(
      security find-generic-password \
        -a "${USER}" \
        -s "wintermute.blackduck.url" \
        -w 2>/dev/null
    )" || return 1
    export BLACKDUCK_URL
  fi

  if [[ -z "${BLACKDUCK_API_TOKEN:-}" ]]; then
    BLACKDUCK_API_TOKEN="$(
      security find-generic-password \
        -a "${USER}" \
        -s "wintermute.blackduck.api-token" \
        -w 2>/dev/null
    )" || return 1
    export BLACKDUCK_API_TOKEN
  fi

  [[ -n "${BLACKDUCK_URL}" && -n "${BLACKDUCK_API_TOKEN}" ]]
}

_wintermute_load_blackduck_env
_wintermute_load_exit=$?
unfunction _wintermute_load_blackduck_env
return "${_wintermute_load_exit}"
