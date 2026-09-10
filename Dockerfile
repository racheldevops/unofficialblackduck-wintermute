FROM python:3.12.10-slim-bookworm AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip wheel \
        --no-deps \
        --wheel-dir /build/wheels \
        .


FROM python:3.12.10-slim-bookworm AS bridge-bundle

ARG TARGETARCH
ARG BRIDGE_BUNDLE_AMD64_URL=https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle/latest/bridge-cli-bundle-linux64.zip
ARG BRIDGE_BUNDLE_AMD64_SHA256
ARG BRIDGE_BUNDLE_ARM64_URL=https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle/latest/bridge-cli-bundle-linux_arm.zip
ARG BRIDGE_BUNDLE_ARM64_SHA256
ARG BRIDGE_BUNDLE_INSECURE=false

ENV PYTHONDONTWRITEBYTECODE=1

COPY scripts/install_bridge_bundle.py \
    /usr/local/bin/install-bridge-bundle

RUN set -eu; \
    case "${TARGETARCH}" in \
        amd64) \
            bundle_url="${BRIDGE_BUNDLE_AMD64_URL}"; \
            bundle_sha256="${BRIDGE_BUNDLE_AMD64_SHA256}"; \
            ;; \
        arm64) \
            bundle_url="${BRIDGE_BUNDLE_ARM64_URL}"; \
            bundle_sha256="${BRIDGE_BUNDLE_ARM64_SHA256}"; \
            ;; \
        *) \
            echo "Unsupported scan image architecture: ${TARGETARCH}" >&2; \
            exit 2; \
            ;; \
    esac; \
    test -n "${bundle_url}"; \
    test -n "${bundle_sha256}"; \
    case "${BRIDGE_BUNDLE_INSECURE}" in \
        true) set -- --insecure ;; \
        false) set -- ;; \
        *) \
            echo "BRIDGE_BUNDLE_INSECURE must be true or false" >&2; \
            exit 2; \
            ;; \
    esac; \
    python \
        /usr/local/bin/install-bridge-bundle \
        --url "${bundle_url}" \
        --sha256 "${bundle_sha256}" \
        --output /bridge \
        "$@"; \
    test -x /bridge/bridge-cli


FROM python:3.12.10-slim-bookworm AS runtime-base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    WINTERMUTE_OUTPUT_DIR=/var/lib/blackduck-wintermute \
    TMPDIR=/tmp

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 wintermute \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --no-create-home \
        --shell /usr/sbin/nologin \
        wintermute \
    && install \
        --directory \
        --owner wintermute \
        --group wintermute \
        --mode 0770 \
        /var/lib/blackduck-wintermute \
    && install \
        --directory \
        --owner wintermute \
        --group wintermute \
        --mode 0755 \
        /app

COPY --from=build /build/wheels /tmp/wheels

RUN python -m pip install \
        --no-cache-dir \
        /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels

WORKDIR /app
USER 10001:10001


FROM runtime-base AS source

ENTRYPOINT ["blackduck-wintermute-cohort-source"]
CMD ["--scope", "parent-rollup", "--strict", "--resolve-bom-names", "--workers", "8", "--component-workers", "2", "--page-limit", "500", "--minimum-score", "7", "--skip-policy-rule-details", "--lineage-cache-max-age-days", "7", "--trust-lineage-cache-without-update-marker"]


FROM runtime-base AS jira

ENTRYPOINT ["blackduck-wintermute-jira-cohort"]
CMD ["--dry-run", "--strict"]


FROM runtime-base AS datadog

ENTRYPOINT ["blackduck-wintermute-datadog-cohort"]
CMD ["--dry-run", "--strict"]


FROM runtime-base AS scm

ENTRYPOINT ["blackduck-wintermute-scm-overview"]
CMD ["--workers", "1", "--evidence-workers", "1", "--scan-evidence-workers", "1", "--page-limit", "100", "--max-hours", "2"]


FROM runtime-base AS scan

USER root

COPY --from=bridge-bundle \
    --chown=10001:10001 \
    /bridge \
    /opt/blackduck/bridge

RUN install \
        --directory \
        --owner wintermute \
        --group wintermute \
        --mode 0755 \
        /workspace \
    && test -x \
        /opt/blackduck/bridge/bridge-cli

ENV PATH=/opt/blackduck/bridge:${PATH} \
    BLACKDUCK_BRIDGE_PATH=/opt/blackduck/bridge/bridge-cli \
    HOME=/tmp/wintermute-home \
    XDG_CACHE_HOME=/tmp/wintermute-cache \
    XDG_CONFIG_HOME=/tmp/wintermute-config

WORKDIR /workspace
USER 10001:10001

ENTRYPOINT ["blackduck-wintermute-scan"]
CMD ["--mode", "dry-run"]


FROM runtime-base AS runtime

ENTRYPOINT ["blackduck-jira-pipeline"]
CMD ["--dry-run", "--strict", "--resolve-bom-names", "--workers", "8", "--parent-workers", "8", "--rollup-workers", "8"]
