#!/bin/zsh
emulate -L zsh
exec >/dev/null 2>&1

root="${0:A:h:h}"
results_dir="${root}/.benchmark-results"
mkdir -p "${results_dir}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
launcher_log="${results_dir}/launcher-${timestamp}.log"
status_file="${results_dir}/last-launch-exit-code.txt"

if [[ -x "${root}/.venv/bin/python" ]]; then
  python_bin="${root}/.venv/bin/python"
else
  python_bin="python3"
fi

"${python_bin}" \
  "${root}/scripts/scaling_benchmark.py" \
  --config "${root}/scripts/scaling_benchmark.json" \
  "$@" >"${launcher_log}" 2>&1

status=$?
printf '%s\n' "${status}" >"${status_file}"
exit 0
