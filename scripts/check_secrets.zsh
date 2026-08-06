#!/bin/zsh
emulate -L zsh
set -euo pipefail

root="${0:A:h:h}"

if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/ggshield" ]]; then
  scanner="${VIRTUAL_ENV}/bin/ggshield"
elif [[ -x "${root}/.venv/bin/ggshield" ]]; then
  scanner="${root}/.venv/bin/ggshield"
elif command -v ggshield >/dev/null 2>&1; then
  scanner="$(command -v ggshield)"
else
  print -u2 "ggshield is not installed"
  exit 1
fi

cd "${root}"

"${scanner}" secret scan repo .

if ! git diff --cached --quiet; then
  "${scanner}" secret scan pre-commit
fi

git diff --check
