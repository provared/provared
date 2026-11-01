# A demonstration of the Provared MCP executor, in front of a made-up tool
# server. DEMONSTRATION ONLY: its permission is signed by the library's
# development stand-in for a passkey, and its records prove nothing about
# any person. See README.md in this folder.
#
# Build from the top of the repository (the build reads mcp-executor/demo/):
#
#   docker build -f mcp-executor/demo/Dockerfile -t provared-mcp-executor-demo .
#   docker run -i --rm provared-mcp-executor-demo
#
# The container speaks MCP over its standard input and output. To try a
# packed copy of the executor before it is published, put the .tgz file in
# mcp-executor/demo/ and add
#   --build-arg EXECUTOR=file:./provared-mcp-executor-0.2.0.tgz

# Node.js 24.22.2 on Debian 12 (bookworm), slim: the official image, pinned
# by its version and by the digest of its multi-platform index, read from
# Docker Hub on 1 November 2026.
FROM node:24.22.2-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c

WORKDIR /demo
COPY mcp-executor/demo/ ./

# The library and the executor from npm, at the exact versions package.json
# names; no install scripts run. EXECUTOR, where given, replaces the
# executor's version (a packed file, for a test before publishing).
ARG EXECUTOR=
RUN if [ -n "$EXECUTOR" ]; then npm pkg set "dependencies.provared-mcp-executor=$EXECUTOR"; fi \
 && npm install --omit=dev --ignore-scripts --no-audit --no-fund

# The demonstration's keys, permission, book and copy are made on the first
# start, in the home folder of the image's own unprivileged user.
USER node
ENV PROVARED_DEMO_DIR=/home/node/provared-demo
CMD ["node", "/demo/start.mjs"]
