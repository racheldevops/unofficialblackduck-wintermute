#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

root="${0:A:h:h}"
output_dir="${root}/.wintermute/bridge-download"
insecure="${BRIDGE_BUNDLE_INSECURE:-false}"

amd64_url="${BRIDGE_BUNDLE_AMD64_URL:-https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle/latest/bridge-cli-bundle-linux64.zip}"
arm64_url="${BRIDGE_BUNDLE_ARM64_URL:-https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle/latest/bridge-cli-bundle-linux_arm.zip}"

case "${insecure:l}" in
  true)
    tls_arguments=(--insecure)
    ;;
  false)
    tls_arguments=()
    ;;
  *)
    print -u2 "BRIDGE_BUNDLE_INSECURE must be true or false"
    return 2 2>/dev/null || exit 2
    ;;
esac

mkdir -p "${output_dir}"

print "Calculating AMD64 Bridge bundle SHA-256..."
amd64_sha256="$(
  python "${root}/scripts/install_bridge_bundle.py" \
    --url "${amd64_url}" \
    --print-sha256 \
    "${tls_arguments[@]}"
)"

print "Calculating ARM64 Bridge bundle SHA-256..."
arm64_sha256="$(
  python "${root}/scripts/install_bridge_bundle.py" \
    --url "${arm64_url}" \
    --print-sha256 \
    "${tls_arguments[@]}"
)"

for value in "${amd64_sha256}" "${arm64_sha256}"; do
  if [[ ! "${value}" =~ '^[0-9a-f]{64}$' ]]; then
    print -u2 "Bridge bundle SHA-256 validation failed"
    return 2 2>/dev/null || exit 2
  fi
done

cat > "${output_dir}/pins.env" <<EOF
export BRIDGE_BUNDLE_AMD64_URL='${amd64_url}'
export BRIDGE_BUNDLE_AMD64_SHA256='${amd64_sha256}'
export BRIDGE_BUNDLE_ARM64_URL='${arm64_url}'
export BRIDGE_BUNDLE_ARM64_SHA256='${arm64_sha256}'
EOF

cat > "${output_dir}/pins.json" <<EOF
{
  "amd64": {
    "url": "${amd64_url}",
    "sha256": "${amd64_sha256}"
  },
  "arm64": {
    "url": "${arm64_url}",
    "sha256": "${arm64_sha256}"
  }
}
EOF

print
print "Bridge bundle pins written to:"
print "  ${output_dir}/pins.env"
print "  ${output_dir}/pins.json"
print
print "AMD64: ${amd64_sha256}"
print "ARM64: ${arm64_sha256}"
