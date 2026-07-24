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

FROM python:3.12.10-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HARNESS_OUTPUT_DIR=/var/lib/blackduck-harness \
    TMPDIR=/tmp

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 harness \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --no-create-home \
        --shell /usr/sbin/nologin \
        harness \
    && install \
        --directory \
        --owner harness \
        --group harness \
        --mode 0770 \
        /var/lib/blackduck-harness \
    && install \
        --directory \
        --owner harness \
        --group harness \
        --mode 0755 \
        /app

COPY --from=build /build/wheels /tmp/wheels

RUN python -m pip install \
        --no-cache-dir \
        /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels

WORKDIR /app
USER 10001:10001

ENTRYPOINT ["blackduck-jira-pipeline"]
CMD ["--dry-run"]
