#!/bin/zsh
emulate -L zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL

root="${0:A:h:h}"
image="${SCAN_IMAGE:?SCAN_IMAGE is required}"
insecure="${BRIDGE_BUNDLE_INSECURE:-false}"

: "${BRIDGE_BUNDLE_AMD64_URL:?BRIDGE_BUNDLE_AMD64_URL is required}"
: "${BRIDGE_BUNDLE_AMD64_SHA256:?BRIDGE_BUNDLE_AMD64_SHA256 is required}"
: "${BRIDGE_BUNDLE_ARM64_URL:?BRIDGE_BUNDLE_ARM64_URL is required}"
: "${BRIDGE_BUNDLE_ARM64_SHA256:?BRIDGE_BUNDLE_ARM64_SHA256 is required}"

if [[ "${image}" == *":latest" ]]; then
  print -u2 "SCAN_IMAGE must not use the latest tag"
  return 2 2>/dev/null || exit 2
fi

if [[ "${image}" != *:* ]]; then
  print -u2 "SCAN_IMAGE must include an immutable release tag"
  return 2 2>/dev/null || exit 2
fi

for value in \
  "${BRIDGE_BUNDLE_AMD64_SHA256}" \
  "${BRIDGE_BUNDLE_ARM64_SHA256}"
do
  if [[ ! "${value}" =~ '^[0-9a-f]{64}$' ]]; then
    print -u2 "Invalid Bridge bundle SHA-256"
    return 2 2>/dev/null || exit 2
  fi
done

case "${insecure:l}" in
  true|false)
    ;;
  *)
    print -u2 "BRIDGE_BUNDLE_INSECURE must be true or false"
    return 2 2>/dev/null || exit 2
    ;;
esac

cd "${root}"

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --target scan \
  --build-arg "BRIDGE_BUNDLE_AMD64_URL=${BRIDGE_BUNDLE_AMD64_URL}" \
  --build-arg "BRIDGE_BUNDLE_AMD64_SHA256=${BRIDGE_BUNDLE_AMD64_SHA256}" \
  --build-arg "BRIDGE_BUNDLE_ARM64_URL=${BRIDGE_BUNDLE_ARM64_URL}" \
  --build-arg "BRIDGE_BUNDLE_ARM64_SHA256=${BRIDGE_BUNDLE_ARM64_SHA256}" \
  --build-arg "BRIDGE_BUNDLE_INSECURE=${insecure:l}" \
  --tag "${image}" \
  --push \
  .
