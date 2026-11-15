# SPDX-FileCopyrightText: 2026 StarHub Contributors
# SPDX-License-Identifier: MIT
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/bin:${PATH}"

WORKDIR /app

RUN groupadd --gid 10001 starhub \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin starhub

COPY --chown=10001:10001 bin ./bin
COPY --chown=10001:10001 profiles ./profiles
COPY --chown=10001:10001 scripts ./scripts
COPY --chown=10001:10001 templates ./templates
COPY --chown=10001:10001 LICENSE README.md STARHUB_GROUND_TRUTH.json topology.example.json ./

USER 10001:10001

CMD ["python3", "/app/scripts/starhub-ctl.py", "--repo-root", "/app", "mcp"]
