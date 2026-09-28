#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

root="${0:A:h:h}"
cd "${root}"

if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
  python_bin="${VIRTUAL_ENV}/bin/python"
elif [[ -x "${root}/.venv/bin/python" ]]; then
  python_bin="${root}/.venv/bin/python"
elif command -v python3.12 >/dev/null 2>&1; then
  python_bin="$(command -v python3.12)"
elif command -v python3 >/dev/null 2>&1; then
  python_bin="$(command -v python3)"
else
  print -u2 "Activate your Python 3.12 virtualenv first."
  exit 2
fi

exec "${python_bin}" "${root}/scripts/run_product_benchmark.py" "$@"
