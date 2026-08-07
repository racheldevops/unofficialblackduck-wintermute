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

FROM runtime-base AS runtime

ENTRYPOINT ["blackduck-jira-pipeline"]
CMD ["--dry-run", "--strict", "--resolve-bom-names", "--workers", "8", "--parent-workers", "8", "--rollup-workers", "8"]
