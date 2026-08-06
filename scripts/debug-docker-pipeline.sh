#!/usr/bin/env bash
set -uo pipefail

config_path="$PWD/src/wintermute/jira/config/jira-rollup-config.json"
volume_name="blackduck-wintermute-data"
image_name="blackduck-wintermute:local"

required_variables=(
    BLACKDUCK_URL
    BLACKDUCK_API_TOKEN
    JIRA_URL
    JIRA_USER
    JIRA_API_TOKEN
)

printf '\n=== Host process ===\n'
printf 'Working directory: %s\n' "$PWD"
printf 'Bash version: %s\n' "$BASH_VERSION"
printf 'Python: %s\n' "$(command -v python || printf 'missing')"
printf 'Docker: %s\n' "$(command -v docker || printf 'missing')"

python - <<'PYTHON'
from __future__ import annotations

import os
import sys
from urllib.parse import urlsplit

names = [
    "BLACKDUCK_URL",
    "BLACKDUCK_API_TOKEN",
    "JIRA_URL",
    "JIRA_USER",
    "JIRA_API_TOKEN",
]

missing = []

print()
print("=== IntelliJ process environment ===")

for name in names:
    value = os.environ.get(name)

    if value is None:
        print(f"{name}: MISSING")
        missing.append(name)
        continue

    encoded = value.encode("utf-8")
    leading_whitespace = bool(value[:1].isspace())
    trailing_whitespace = bool(value[-1:].isspace())

    print(
        f"{name}: set; "
        f"characters={len(value)}; "
        f"bytes={len(encoded)}; "
        f"empty={not bool(value)}; "
        f"leading_whitespace={leading_whitespace}; "
        f"trailing_whitespace={trailing_whitespace}; "
        f"contains_CR={chr(13) in value}; "
        f"contains_LF={chr(10) in value}"
    )

    if name.endswith("_URL") and value:
        parsed = urlsplit(value)
        print(
            f"  parsed scheme={parsed.scheme!r}; "
            f"hostname={parsed.hostname!r}; "
            f"port={parsed.port!r}"
        )

if missing:
    print(
        "ERROR: missing host variables: "
        + ", ".join(missing),
        file=sys.stderr,
    )
    raise SystemExit(2)

if any(not os.environ.get(name) for name in names):
    print(
        "ERROR: at least one required variable is empty",
        file=sys.stderr,
    )
    raise SystemExit(2)
PYTHON

host_environment_rc=$?

if [[ "$host_environment_rc" -ne 0 ]]; then
    printf '\nHost environment diagnostic failed with exit code %s\n' \
        "$host_environment_rc" >&2
    exit "$host_environment_rc"
fi

printf '\n=== Host files ===\n'

if [[ -f "$config_path" ]]; then
    printf 'Jira config exists: %s\n' "$config_path"
else
    printf 'ERROR: Jira config is missing: %s\n' "$config_path" >&2
    exit 2
fi

if ! docker info >/dev/null 2>&1; then
    printf 'ERROR: Docker daemon is not available\n' >&2
    exit 2
fi

if ! docker image inspect "$image_name" >/dev/null 2>&1; then
    printf 'ERROR: Docker image does not exist: %s\n' "$image_name" >&2
    exit 2
fi

docker image inspect "$image_name" \
    --format 'Image ID={{.Id}} Created={{.Created}} Architecture={{.Architecture}} OS={{.Os}}'

docker volume inspect "$volume_name" >/dev/null 2>&1 ||
    docker volume create "$volume_name" >/dev/null

printf 'Docker volume exists: %s\n' "$volume_name"

printf '\n=== Installed container pipeline options ===\n'

pipeline_help="$(
    docker run \
        --rm \
        "$image_name" \
        --help
)"
help_rc=$?

if [[ "$help_rc" -ne 0 ]]; then
    printf 'ERROR: container pipeline help failed with exit code %s\n' \
        "$help_rc" >&2
    exit "$help_rc"
fi

expected_options=(
    --dry-run
    --strict
    --resolve-bom-names
    --refresh-parents
    --parent-timeout
    --parent-retries
    --parent-workers
    --rollup-timeout
    --rollup-retries
    --hierarchy-limit
    --refresh-existing-jira
    --insecure
)

missing_options=0

for option in "${expected_options[@]}"; do
    if grep -Fq -- "$option" <<<"$pipeline_help"; then
        printf '%s: available\n' "$option"
    else
        printf '%s: MISSING FROM IMAGE\n' "$option" >&2
        missing_options=1
    fi
done

if [[ "$missing_options" -ne 0 ]]; then
    printf '\nERROR: the image is older than the current pipeline source.\n' >&2
    printf 'Rebuild with:\n' >&2
    printf 'docker build --pull --file Dockerfile --tag %s .\n' \
        "$image_name" >&2
    exit 2
fi

printf '\n=== Container environment and mounted config ===\n'

docker run \
    --rm \
    --env BLACKDUCK_URL \
    --env BLACKDUCK_API_TOKEN \
    --env JIRA_URL \
    --env JIRA_USER \
    --env JIRA_API_TOKEN \
    --mount "type=bind,source=$config_path,target=/etc/blackduck-wintermute/jira-rollup-config.json,readonly" \
    --entrypoint python \
    "$image_name" \
    -c '
from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlsplit

names = [
    "BLACKDUCK_URL",
    "BLACKDUCK_API_TOKEN",
    "JIRA_URL",
    "JIRA_USER",
    "JIRA_API_TOKEN",
]

missing = []

for name in names:
    value = os.environ.get(name)

    if value is None:
        print(f"{name}: MISSING")
        missing.append(name)
        continue

    print(
        f"{name}: set; "
        f"characters={len(value)}; "
        f"bytes={len(value.encode(chr(117) + chr(116) + chr(102) + chr(45) + chr(56)))}; "
        f"empty={not bool(value)}; "
        f"leading_whitespace={bool(value[:1].isspace())}; "
        f"trailing_whitespace={bool(value[-1:].isspace())}; "
        f"contains_CR={chr(13) in value}; "
        f"contains_LF={chr(10) in value}"
    )

    if name.endswith("_URL") and value:
        parsed = urlsplit(value)
        print(
            f"  parsed scheme={parsed.scheme!r}; "
            f"hostname={parsed.hostname!r}; "
            f"port={parsed.port!r}"
        )

config_path = "/etc/blackduck-wintermute/jira-rollup-config.json"

with open(config_path, encoding="utf-8") as input_file:
    config = json.load(input_file)

jira = config.get("jira", {})

print()
print(f"Config readable: {config_path}")
print(f"Config project_key: {jira.get(chr(112) + chr(114) + chr(111) + chr(106) + chr(101) + chr(99) + chr(116) + chr(95) + chr(107) + chr(101) + chr(121))!r}")
print(f"Config auth_mode: {jira.get(chr(97) + chr(117) + chr(116) + chr(104) + chr(95) + chr(109) + chr(111) + chr(100) + chr(101), chr(98) + chr(97) + chr(115) + chr(105) + chr(99))!r}")
print(f"Config verify_tls: {jira.get(chr(118) + chr(101) + chr(114) + chr(105) + chr(102) + chr(121) + chr(95) + chr(116) + chr(108) + chr(115))!r}")

if missing:
    print(
        "ERROR: Docker did not receive: "
        + ", ".join(missing),
        file=sys.stderr,
    )
    raise SystemExit(2)

if any(not os.environ.get(name) for name in names):
    print(
        "ERROR: at least one container variable is empty",
        file=sys.stderr,
    )
    raise SystemExit(2)
'

container_probe_rc=$?

if [[ "$container_probe_rc" -ne 0 ]]; then
    printf '\nContainer environment probe failed with exit code %s\n' \
        "$container_probe_rc" >&2
    exit "$container_probe_rc"
fi

printf '\n=== Starting full container dry run ===\n'

docker run \
    --rm \
    --env BLACKDUCK_URL \
    --env BLACKDUCK_API_TOKEN \
    --env JIRA_URL \
    --env JIRA_USER \
    --env JIRA_API_TOKEN \
    --mount "type=volume,source=$volume_name,target=/var/lib/blackduck-wintermute" \
    --mount "type=bind,source=$config_path,target=/etc/blackduck-wintermute/jira-rollup-config.json,readonly" \
    "$image_name" \
    --dry-run \
    --strict \
    --resolve-bom-names \
    --refresh-parents \
    --parent-timeout 90 \
    --parent-retries 2 \
    --parent-workers 3 \
    --rollup-timeout 30 \
    --rollup-retries 1 \
    --threshold 7 \
    --page-limit 500 \
    --hierarchy-limit 50 \
    --refresh-existing-jira \
    --insecure \
    --config /etc/blackduck-wintermute/jira-rollup-config.json \
    --debug

pipeline_rc=$?

printf '\n=== Final result ===\n'
printf 'Container pipeline exit code: %s\n' "$pipeline_rc"

exit "$pipeline_rc"
