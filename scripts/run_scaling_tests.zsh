#!/bin/zsh
emulate -L zsh
exec >/dev/null 2>&1

root="${0:A:h:h}"
results_dir="${root}/.test-results"
mkdir -p "${results_dir}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
test_log="${results_dir}/scaling-benchmark-${timestamp}.log"
status_file="${results_dir}/last-scaling-test-exit-code.txt"

if [[ -x "${root}/.venv/bin/python" ]]; then
  python_bin="${root}/.venv/bin/python"
else
  python_bin="python3"
fi

cd "${root}" || {
  printf '%s\n' "1" >"${status_file}"
  exit 0
}

"${python_bin}" -m pytest \
  -q \
  tests/test_scaling_benchmark.py >"${test_log}" 2>&1

status=$?
printf '%s\n' "${status}" >"${status_file}"
exit 0
