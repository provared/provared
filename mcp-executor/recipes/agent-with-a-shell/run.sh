#!/bin/sh
# run.sh: runs the whole example. Needs Docker and the image node:24, and network access for npm.
# Run it from this folder:  sh run.sh
# It makes three containers (provared-example-guard, provared-example-tools-server, provared-example-agent) and two networks
# (provared-example-agent, and provared-example-tools which is --internal), runs seven checks, prints each as
# PASSED or FAILED, and removes the containers and networks by name, even after a failure.
# All secrets are made fresh inside the guard container (/data) and are never written
# to this folder; they go when the container is removed.
# The slip is signed with the library's DEVELOPMENT STAND-IN for a passkey. A real slip is
# signed by a person with a passkey.
export MSYS_NO_PATHCONV=1   # Git Bash on Windows: do not rewrite /paths given to docker
MSYS2_ARG_CONV_EXCL='*'; export MSYS2_ARG_CONV_EXCL
cd "$(dirname "$0")" || exit 1

G=provared-example-guard; S=provared-example-tools-server; A=provared-example-agent
NA=provared-example-agent; NT=provared-example-tools
IMG=node:24
FAILS=0

cleanup() {
  docker rm -f "$A" "$S" "$G" >/dev/null 2>&1
  docker network rm "$NA" "$NT" >/dev/null 2>&1
  echo "cleanup: containers $G $S $A and networks $NA $NT removed"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

die() { echo "ERROR: $*"; exit 1; }
step() { echo "== $*"; }

# wait_for SECONDS DESCRIPTION COMMAND...  (polls once a second; fails the run at the limit)
wait_for() {
  n=$1; d=$2; shift 2
  while [ "$n" -gt 0 ]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    n=$((n - 1)); sleep 1
  done
  die "timed out waiting for $d"
}

report() { # report NUMBER PASS|FAIL DESCRIPTION
  if [ "$2" = pass ]; then echo "CHECK $1: PASSED - $3"; else echo "CHECK $1: FAILED - $3"; FAILS=$((FAILS + 1)); fi
}
has() { printf '%s\n' "$1" | grep -Eq -- "$2"; }

# Remove anything left from an earlier run (by name only).
docker rm -f "$A" "$S" "$G" >/dev/null 2>&1
docker network rm "$NA" "$NT" >/dev/null 2>&1

step "networks and containers"
docker network create "$NA" >/dev/null || die "network $NA"
docker network create --internal "$NT" >/dev/null || die "network $NT"
docker run -d --name "$G" --network "$NA" "$IMG" tail -f /dev/null >/dev/null || die "guard container"
docker network connect "$NT" "$G" || die "connect guard to $NT"
docker run -d --name "$S" --network "$NT" "$IMG" tail -f /dev/null >/dev/null || die "tool server container"
docker run -d --name "$A" --network "$NA" "$IMG" tail -f /dev/null >/dev/null || die "agent container"
docker exec "$G" mkdir -p /data /sdk /work
docker exec "$S" mkdir -p /work /secret
docker exec "$A" mkdir -p /work

step "install provared-mcp-executor@0.3.0 in the guard container"
docker exec "$G" sh -c 'cd /data && npm init -y >/dev/null && timeout 300 npm install --ignore-scripts provared-mcp-executor@0.3.0 2>&1 | tail -3' || die "npm install of the executor"
docker exec "$G" sh -c 'cd /data && ls node_modules' | tr '\n' ' '; echo

step "install the SDK (1.32.2) for the stand-in server and client; the guard has the outside route, the other two do not"
docker cp package.json "$G":/sdk/package.json || die "copy package.json"
docker exec "$G" sh -c 'cd /sdk && timeout 300 npm install --ignore-scripts 2>&1 | tail -3' || die "npm install of the SDK"
for c in "$S" "$A"; do
  docker exec "$G" tar -C /sdk -cf - node_modules | docker exec -i "$c" tar -C / -xf - || die "copy SDK to $c"
done

step "copy the scripts"
docker cp guard-setup.mjs "$G":/data/guard-setup.mjs || die cp
docker cp guard-checkbook.mjs "$G":/data/guard-checkbook.mjs || die cp
docker cp proxy.mjs "$G":/data/proxy.mjs || die cp
docker cp tool-server.mjs "$S":/work/tool-server.mjs || die cp
docker cp agent-client.mjs "$A":/work/agent-client.mjs || die cp
docker cp agent-checks.sh "$A":/work/agent-checks.sh || die cp

step "make keys, a slip, the token, the agent secret and the settings (slip signed with the DEVELOPMENT stand-in passkey, not a real one)"
docker exec "$G" sh -c 'cd /data && node guard-setup.mjs' || die "guard-setup"

step "make the certificate"
docker exec "$G" sh -c 'mkdir -p /data/tls && openssl req -x509 -newkey rsa:2048 -nodes -keyout /data/tls/key.pem -out /data/tls/cert.pem -days 2 -subj /CN=provared-example-guard -addext subjectAltName=DNS:provared-example-guard 2>/dev/null' || die "certificate"

step "hand each container only what it needs"
docker exec "$G" cat /data/out-token | docker exec -i "$S" sh -c 'cat > /secret/token' || die "token to tool server"
docker exec "$G" rm -f /data/out-token
docker exec "$G" cat /data/tls/cert.pem | docker exec -i "$A" sh -c 'cat > /work/ca.pem' || die "certificate to agent"
AGENT_SECRET=$(docker exec "$G" cat /data/out-agent-secret) || die "agent secret"
docker exec "$G" rm -f /data/out-agent-secret
export AGENT_SECRET   # never printed; passed to the agent container by name only

step "start the tool server, the guard (127.0.0.1:8796) and the TLS proxy (8443)"
docker exec -d "$S" sh -c 'cd /work && exec node tool-server.mjs > /work/server.log 2>&1'
wait_for 60 "tool server" docker exec "$S" grep -q listening /work/server.log
docker exec -d "$G" sh -c 'cd /data/guard && exec node /data/node_modules/provared-mcp-executor/bin.mjs http --config executor-http.json > /data/guard.log 2>&1'
wait_for 60 "guard" docker exec "$G" grep -qi listening /data/guard.log
docker exec -d "$G" sh -c 'cd /data && exec node proxy.mjs > /data/proxy.log 2>&1'
wait_for 60 "proxy" docker exec "$G" grep -q "proxy listening" /data/proxy.log
echo "--- guard start-up output:"; docker exec "$G" cat /data/guard.log | sed 's/^/    /'

step "run the client in the agent container (with the certificate)"
AGENT_CTX="-e AGENT_SECRET -e NODE_EXTRA_CA_CERTS=/work/ca.pem"
CLIENT_OUT=$(timeout 120 docker exec $AGENT_CTX "$A" sh -c 'cd /work && node agent-client.mjs') || die "client run"
echo "$CLIENT_OUT" | sed 's/^/    /'

step "run the checks in the agent container"
AGENT_OUT=$(timeout 180 docker exec $AGENT_CTX "$A" sh /work/agent-checks.sh) || die "agent checks"
echo "$AGENT_OUT" | sed 's/^/    /'

step "run the client without the certificate (it should fail)"
REQS_BEFORE=$(docker exec "$S" cat /work/server.log | grep -c '^REQ ')
NOCA_OUT=$(timeout 120 docker exec -e AGENT_SECRET -e NODE_EXTRA_CA_CERTS= "$A" sh -c 'cd /work && node agent-client.mjs' 2>&1)
echo "$NOCA_OUT" | sed 's/^/    /'
REQS_AFTER=$(docker exec "$S" cat /work/server.log | grep -c '^REQ ')

step "guard-side checks: the book, the comparison, and a search for the token prefix"
BOOK_OUT=$(docker exec "$G" sh -c 'cd /data && node guard-checkbook.mjs' 2>&1)
echo "$BOOK_OUT" | sed 's/^/    /'
CMP_OUT=$(docker exec "$G" sh -c 'cd /data/guard && node /data/node_modules/provared-mcp-executor/bin.mjs compare --config executor-http.json --agent alpha' 2>&1)
echo "$CMP_OUT" | sed 's/^/    /'
CONTROL=$(docker exec "$G" sh -c 'grep -rl "UPSTREAM-TOKEN-" /data/guard/secrets | wc -l')
GUARD_HITS=$(docker exec "$G" sh -c 'grep -rl "UPSTREAM-TOKEN-" /data/guard/books /data/guard/copies /data/guard.log /data/proxy.log 2>/dev/null | wc -l')
echo "    control (token file holds the prefix): $CONTROL file; book, copy and logs holding it: $GUARD_HITS"
SERVER_LOG=$(docker exec "$S" cat /work/server.log)
echo "--- tool server log:"; echo "$SERVER_LOG" | sed 's/^/    /'

echo
echo "================ RESULTS ================"
echo "(slip signed with the development stand-in passkey; a real slip is signed by a person with a passkey)"

# 1 TLS
if has "$CLIENT_OUT" 'protocol=TLSv1\.3' && has "$CLIENT_OUT" 'authorized=true'; then
  report 1 pass "TLS 1.3 to the guard, certificate accepted"; else report 1 fail "TLS 1.3 to the guard, certificate accepted"; fi

# 2 allowed ran, other refused and never reached the tool server
RAN=$(echo "$SERVER_LOG" | grep -c '^TOOL-RAN allowed_tool')
OTHER=$(echo "$SERVER_LOG" | grep -c 'other_tool')
if has "$CLIENT_OUT" '\[call allowed_tool\].*hello from allowed_tool' && has "$CLIENT_OUT" 'call other_tool.*(isError":true|refused)' && [ "$RAN" -ge 1 ] && [ "$OTHER" -eq 0 ]; then
  report 2 pass "allowed_tool ran; other_tool refused and never reached the tool server"; else report 2 fail "allowed_tool ran; other_tool refused and never reached the tool server"; fi

# 3 book and copy
if has "$BOOK_OUT" 'problemFound: false' && has "$CMP_OUT" '"agree": *true'; then
  report 3 pass "book has no problem; copy and book agree"; else report 3 fail "book has no problem; copy and book agree"; fi

# 4 the agent holds no token and cannot reach the tool server or the plain port
if has "$AGENT_OUT" 'CHK file-hits=0$' && has "$AGENT_OUT" 'CHK sdk-hits=0$' && has "$AGENT_OUT" 'CHK env-hits=0$' && has "$AGENT_OUT" 'CHK proc-hits=0$' \
  && has "$AGENT_OUT" 'CHK tools-dns=ENOTFOUND' && has "$AGENT_OUT" 'CHK tools-connect=ENOTFOUND' \
  && has "$AGENT_OUT" 'CHK port8796=ECONNREFUSED' && has "$AGENT_OUT" 'CHK port9000=ECONNREFUSED' && [ "$CONTROL" -ge 1 ]; then
  report 4 pass "agent: token prefix in no file, env or /proc; tool server unreachable; plain port refused"; else report 4 fail "agent: token prefix in no file, env or /proc; tool server unreachable; plain port refused"; fi

# 5 nothing received or logged holds the token
if has "$AGENT_OUT" 'CHK received-hits=0$' && [ "$GUARD_HITS" -eq 0 ]; then
  report 5 pass "token prefix not in what the client received, nor in the guard's log, book or copy"; else report 5 fail "token prefix not in what the client received, nor in the guard's log, book or copy"; fi

# 6 without the certificate the client fails and the tool server sees nothing more
if has "$NOCA_OUT" 'DEPTH_ZERO_SELF_SIGNED_CERT' && [ "$REQS_BEFORE" = "$REQS_AFTER" ]; then
  report 6 pass "without the certificate the client fails; tool server request count stayed at $REQS_AFTER"; else report 6 fail "without the certificate the client fails; tool server request count stayed at $REQS_AFTER"; fi

# 7 foreign Origin and wrong secret
if has "$AGENT_OUT" 'CHK origin-evil=403' && has "$AGENT_OUT" 'CHK wrong-secret=401'; then
  report 7 pass "foreign Origin gave 403; wrong secret gave 401"; else report 7 fail "foreign Origin gave 403; wrong secret gave 401"; fi

echo "$FAILS check(s) failed"
[ "$FAILS" -eq 0 ]
