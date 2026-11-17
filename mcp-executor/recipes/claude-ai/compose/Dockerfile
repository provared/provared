# The Provared guard (provared-mcp-executor) for the Docker Compose recipe
# beside this file (compose.yaml; README.md, one folder up). The image is
# built on the server from npm, at the exact versions package.json names; no
# image is published anywhere. compose.yaml builds it:
#
#   docker compose up -d --build
#
# Only package.json and start.mjs are sent to the builder
# (Dockerfile.dockerignore, beside this file; it needs BuildKit, the builder
# of every current Docker): never the data folders beside them.
#
# To try a packed copy of the executor before it is published, hand the
# folder that holds the .tgz file to the builder as a context of its own,
# and name the file (README.md, "Trying a packed copy"):
#
#   docker build -f Dockerfile \
#     --build-context executor-file=<folder holding the .tgz> \
#     --build-arg EXECUTOR=file:/tmp/executor/provared-mcp-executor-0.5.0.tgz .

# Empty unless a folder is handed to the builder under this name.
FROM scratch AS executor-file

# Node.js 24.22.3 on Debian 12 (bookworm), slim: the official image, pinned
# by its version and by the digest of its multi-platform index, read from
# Docker Hub on 17 November 2026.
FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54

WORKDIR /guard
COPY package.json start.mjs ./

# The library and the executor from npm, at the exact versions package.json
# names; no install scripts run. EXECUTOR, where given, replaces the
# executor's version (a packed file, for a test before publishing).
ARG EXECUTOR=
RUN --mount=type=bind,from=executor-file,target=/tmp/executor \
    if [ -n "$EXECUTOR" ]; then npm pkg set "dependencies.provared-mcp-executor=$EXECUTOR"; fi \
 && npm install --omit=dev --ignore-scripts --no-audit --no-fund \
 && npm cache clean --force

# The guard's own unprivileged user, 10001, which owns the data folder
# (compose.yaml gives it the folder). The code stays root's, so the guard
# cannot change it.
RUN groupadd --system --gid 10001 guard \
 && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin guard \
 && mkdir -p /data && chown 10001:10001 /data && chmod 700 /data

USER 10001:10001
ENV NODE_ENV=production PROVARED_DATA=/data
WORKDIR /data
ENTRYPOINT ["node", "/guard/start.mjs"]
