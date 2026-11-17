#!/bin/sh
# The Docker check of the compose recipe (recipes/claude-ai/compose). Not
# part of "npm test": it needs Docker, and builds and starts containers.
#
# On Linux with Docker, from the top of the repository, with a packed copy
# of the executor (npm pack, in mcp-executor/):
#
#   RECIPE=mcp-executor/recipes/claude-ai/compose \
#   HELPERS=mcp-executor/test/recipe-compose \
#   TGZ=<folder>/provared-mcp-executor-0.5.0.tgz \
#   sh mcp-executor/test/recipe-compose/docker-check.sh
#
# It can also run in the official image of the Docker command (docker:cli),
# with the Docker socket handed in, and WORK at the same path for this
# container and for Docker itself, so that the bind mounts land where the
# check reads them:
#
#   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
#     -v /tmp/provared-37e-check:/tmp/provared-37e-check \
#     -v <repository>:/src:ro -v <folder with the .tgz>:/pack:ro \
#     -e RECIPE=/src/mcp-executor/recipes/claude-ai/compose \
#     -e HELPERS=/src/mcp-executor/test/recipe-compose \
#     -e TGZ=/pack/provared-mcp-executor-0.5.0.tgz \
#     docker:29.7.2-cli sh /src/mcp-executor/test/recipe-compose/docker-check.sh
#
# What it does: builds the guard's image from the packed file, starts the
# pair with Caddy's internal certificate authority (tls internal) for a test
# domain, stands in for the person with the library's development stand-in
# for a passkey, and checks, through Caddy, with curl --resolve, what the
# README says. Everything it makes is named provared-37e-check*, and taken
# away at the end.

set -u

: "${RECIPE:?RECIPE: the folder of compose.yaml}"
: "${HELPERS:?HELPERS: the folder of this script}"
: "${TGZ:?TGZ: the packed executor}"
WORK="${WORK:-/tmp/provared-37e-check}"
PROJECT=provared-37e-check
DOMAIN=guard-37e.test
NET="${PROJECT}_default"
CURL_IMAGE='curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93'
TGZ_NAME=$(basename "$TGZ")

passed=0
failed=0
ok() { passed=$((passed + 1)); echo "ok      $*"; }
bad() { failed=$((failed + 1)); echo "FAILED  $*"; }
note() { echo "        $*"; }

dc() { docker compose -p "$PROJECT" --project-directory "$WORK" -f "$WORK/compose.yaml" -f "$WORK/compose.test.yaml" --env-file "$WORK/test.env" "$@"; }

cleanup() {
  dc down --timeout 30 >/dev/null 2>&1
  docker image rm "$PROJECT-guard" "$PROJECT-folders" >/dev/null 2>&1
  rm -rf "$WORK/guard-data" "$WORK/caddy-data" "$WORK/caddy-config"
}

# --- the work folder: the recipe's files, the packed executor, the test's own settings ---
rm -rf "$WORK/guard-data" "$WORK/caddy-data" "$WORK/caddy-config" "$WORK/pack"
mkdir -p "$WORK/pack"
for f in compose.yaml Dockerfile Dockerfile.dockerignore package.json start.mjs Caddyfile; do cp "$RECIPE/$f" "$WORK/$f"; done
cp "$TGZ" "$WORK/pack/$TGZ_NAME"
cp "$HELPERS/sign-test-permission.mjs" "$WORK/sign-test-permission.mjs"
printf 'PROVARED_DOMAIN=%s\n' "$DOMAIN" > "$WORK/test.env"
# The recipe's Caddyfile, with Caddy's internal certificate authority for the test domain.
awk '{ print } /^\{\$PROVARED_DOMAIN\} \{$/ { print "\ttls internal" }' "$RECIPE/Caddyfile" > "$WORK/Caddyfile.test"
grep -q 'tls internal' "$WORK/Caddyfile.test" && ok "the test's Caddyfile is the recipe's, with tls internal" || bad "tls internal was not put in the test's Caddyfile"
# The packed copy as the README's "Trying a packed copy" gives it; then the test's own ports, Caddyfile and wait.
cat > "$WORK/compose.test.yaml" <<EOF
x-packed: &packed
  additional_contexts:
    executor-file: ./pack
  args:
    EXECUTOR: file:/tmp/executor/$TGZ_NAME
services:
  folders:
    build: *packed
  guard:
    build: *packed
    environment:
      PROVARED_WAIT_MS: "2000"
  caddy:
    ports: !override
      - "127.0.0.1:18080:80"
      - "127.0.0.1:18443:443"
    volumes: !override
      - ./Caddyfile.test:/etc/caddy/Caddyfile:ro
      - ./caddy-data:/data
      - ./caddy-config:/config
EOF

# --- the recipe as it is shipped: what it publishes, and no named volume ---
shipped=$(docker compose -p "$PROJECT" --project-directory "$WORK" -f "$WORK/compose.yaml" --env-file "$WORK/test.env" config --format json 2>&1)
if [ $? -eq 0 ]; then ok "the shipped compose.yaml is read by docker compose config"; else bad "docker compose config: $shipped"; fi
unset_domain=$(docker compose -p "$PROJECT" --project-directory "$WORK" -f "$WORK/compose.yaml" --env-file /dev/null config 2>&1)
if [ $? -ne 0 ] && echo "$unset_domain" | grep -q 'Set PROVARED_DOMAIN'; then ok "with no domain set, compose stops and says to set PROVARED_DOMAIN"; else bad "with no domain set, compose did not stop: $unset_domain"; fi
docker compose -p "$PROJECT" --project-directory "$WORK" -f "$WORK/compose.yaml" --env-file "$WORK/test.env" config --volumes > "$WORK/named-volumes.txt" 2>&1
if [ ! -s "$WORK/named-volumes.txt" ]; then ok "the shipped compose.yaml names no Docker volume"; else bad "named volumes: $(cat "$WORK/named-volumes.txt")"; fi

# --- build and start ---
echo "-- building the guard's image from $TGZ_NAME"
if dc build --quiet > "$WORK/build.txt" 2>&1; then ok "the guard's image was built from the packed executor"; else bad "build failed"; tail -n 30 "$WORK/build.txt"; cleanup; exit 1; fi
installed=$(docker run --rm --name provared-37e-check-version --entrypoint node "$PROJECT-guard" -p "require('/guard/node_modules/provared-mcp-executor/package.json').version + ' ' + require('/guard/node_modules/provared/package.json').version")
note "installed in the image: provared-mcp-executor and provared $installed"
if ! dc up -d > "$WORK/up.txt" 2>&1; then bad "docker compose up failed"; cat "$WORK/up.txt"; cleanup; exit 1; fi
ok "docker compose up -d started the pair"

wait_log() { # wait_log <text> <seconds>
  i=0
  while [ "$i" -lt "$2" ]; do
    dc logs --no-log-prefix guard 2>/dev/null | grep -qF "$1" && return 0
    sleep 1; i=$((i + 1))
  done
  return 1
}

if wait_log 'waits for the permission' 120; then ok "the guard's log says it waits for the permission"; else bad "the guard did not reach the wait"; dc logs guard | tail -n 30; fi
echo "-- the guard's log, as the business sees it before the permission:"
dc logs --no-log-prefix guard 2>/dev/null | sed 's/^/   | /'

# --- the person's part, by the development stand-in ---
if dc run --rm --no-deps -T --entrypoint node -v "$WORK/sign-test-permission.mjs:/guard/sign-test-permission.mjs:ro" guard /guard/sign-test-permission.mjs; then ok "the stand-in signed the permission (as the guard's user)"; else bad "the stand-in could not sign"; fi
if wait_log 'Starting the guard' 90; then ok "once the permission was in place, check passed and the guard started"; else bad "the guard did not start"; dc logs guard | tail -n 30; fi
echo "-- the guard's log from the check on:"
dc logs --no-log-prefix guard 2>/dev/null | sed -n '/"check"/,$p' | sed 's/^/   | /'

CADDY=$(dc ps -q caddy)
GUARD=$(dc ps -q guard)
CADDY_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$CADDY")
note "Caddy's address in the test network: $CADDY_IP"

# Caddy's internal root certificate, for curl to trust.
i=0
while [ ! -f "$WORK/caddy-data/caddy/pki/authorities/local/root.crt" ] && [ "$i" -lt 60 ]; do sleep 1; i=$((i + 1)); done
cp "$WORK/caddy-data/caddy/pki/authorities/local/root.crt" "$WORK/ca.crt" && chmod 644 "$WORK/ca.crt"

curlc() { docker run --rm --name provared-37e-check-curl --network "$NET" -v "$WORK/ca.crt:/ca.crt:ro" "$CURL_IMAGE" --silent --show-error --max-time 10 --cacert /ca.crt --resolve "$DOMAIN:443:$CADDY_IP" --resolve "$DOMAIN:80:$CADDY_IP" "$@"; }

# Wait for the guard to answer through Caddy.
i=0
while [ "$i" -lt 60 ]; do
  code=$(curlc -o /dev/null -w '%{http_code}' -X POST "https://$DOMAIN/mcp" 2>/dev/null)
  [ "$code" = "401" ] && break
  sleep 1; i=$((i + 1))
done

# --- through Caddy, with curl --resolve ---
h=$(curlc -D - -o /dev/null -X POST -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' "https://$DOMAIN/mcp" | tr -d '\r')
echo "$h" | grep -q '^HTTP/[0-9.]* 401' && echo "$h" | grep -qi "^www-authenticate: Bearer resource_metadata=\"https://$DOMAIN/.well-known/oauth-protected-resource/mcp\"" \
  && ok "POST /mcp with no token: 401, naming https://$DOMAIN/.well-known/oauth-protected-resource/mcp" \
  || bad "the 401: $h"
note "$(echo "$h" | grep -i '^www-authenticate')"

m=$(curlc "https://$DOMAIN/.well-known/oauth-protected-resource/mcp")
echo "$m" | grep -q "\"resource\":\"https://$DOMAIN/mcp\"" && echo "$m" | grep -q "\"authorization_servers\":\[\"https://$DOMAIN\"\]" \
  && ok "the resource's metadata names https://$DOMAIN/mcp and its server" || bad "the resource's metadata: $m"
note "$m"
a=$(curlc "https://$DOMAIN/.well-known/oauth-authorization-server")
echo "$a" | grep -q "\"issuer\":\"https://$DOMAIN\"" && ok "the server's metadata names the issuer https://$DOMAIN" || bad "the server's metadata: $a"

o=$(curlc -D - -o /dev/null "https://$DOMAIN/oauth/owner" | tr -d '\r')
csp=$(echo "$o" | grep -i '^content-security-policy:' | sed 's/^[^:]*: //')
rp=$(echo "$o" | grep -i '^referrer-policy:' | sed 's/^[^:]*: //')
[ "$csp" = "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" ] && ok "the owner's page: content-security-policy as the README gives it" || bad "the owner's page's content-security-policy: $csp"
note "content-security-policy: $csp"
[ "$rp" = "same-origin" ] && ok "the owner's page: referrer-policy: same-origin" || bad "the owner's page's referrer-policy: $rp"

# The Origin reaches the guard unchanged: the owner's exchanges take only the
# guard's own origin, exactly (403 otherwise), and then read the body (400 for one that is not JSON).
c1=$(curlc -o /dev/null -w '%{http_code}' -X POST -H "Origin: https://$DOMAIN" -H 'content-type: application/json' --data 'not json' "https://$DOMAIN/oauth/owner/challenge")
c2=$(curlc -o /dev/null -w '%{http_code}' -X POST -H "Origin: https://other-37e.test" -H 'content-type: application/json' --data 'not json' "https://$DOMAIN/oauth/owner/challenge")
c3=$(curlc -o /dev/null -w '%{http_code}' -X POST -H "Origin: https://$DOMAIN:443" -H 'content-type: application/json' --data 'not json' "https://$DOMAIN/oauth/owner/challenge")
c4=$(curlc -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' --data 'not json' "https://$DOMAIN/oauth/owner/challenge")
[ "$c1" = "400" ] && [ "$c2" = "403" ] && [ "$c3" = "403" ] && [ "$c4" = "403" ] \
  && ok "Origin reaches the guard unchanged: its own origin passes (400, the body), another origin, the same with :443, and none are refused (403)" \
  || bad "Origin: own $c1, other $c2, with :443 $c3, none $c4 (expected 400, 403, 403, 403)"
r80=$(curlc -o /dev/null -w '%{http_code} %{redirect_url}' "http://$DOMAIN/mcp")
note "port 80: $r80"
echo "$r80" | grep -q "^30[18] https://$DOMAIN/mcp" && ok "port 80 sends the browser on to https, path unchanged" || bad "port 80: $r80"

# --- the guard's port: from Caddy alone ---
p=$(docker port "$CADDY" | sort | tr '\n' ' ')
note "Caddy's published ports: $p"
echo "$p" | grep -q '443/tcp' && echo "$p" | grep -q '80/tcp' && [ "$(docker port "$CADDY" | grep -cv -e '^80/tcp' -e '^443/tcp')" = "0" ] \
  && ok "only Caddy's 80 and 443 are published" || bad "published ports: $p"
gp=$(docker inspect -f '{{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}' "$GUARD")
note "the guard's network: $gp"
echo "$gp" | grep -q "^container:$CADDY" && echo "$gp" | grep -qE ' (\{\}|null)$' && ok "the guard has Caddy's network and publishes no port" || bad "the guard's network: $gp"
curlc -o /dev/null --max-time 5 "http://$CADDY_IP:8796/mcp" 2>/dev/null && bad "the guard's port answered at $CADDY_IP:8796, from the test network" || ok "the guard's port does not answer from the test network ($CADDY_IP:8796)"
docker run --rm --name provared-37e-check-curl --network host "$CURL_IMAGE" --silent --max-time 5 -o /dev/null "http://127.0.0.1:8796/mcp" 2>/dev/null && bad "the guard's port answered on the host, at 127.0.0.1:8796" || ok "the guard's port does not answer on the host (127.0.0.1:8796)"
hc=$(docker run --rm --name provared-37e-check-curl --network host -v "$WORK/ca.crt:/ca.crt:ro" "$CURL_IMAGE" --silent --max-time 5 --cacert /ca.crt --resolve "$DOMAIN:18443:127.0.0.1" -o /dev/null -w '%{http_code}' -X POST "https://$DOMAIN:18443/mcp")
[ "$hc" = "401" ] && ok "on the host, Caddy's published port answers (401), so the refusal above is the guard's port's alone" || bad "on the host, Caddy's port answered $hc"

# --- how the containers run ---
gi=$(docker inspect -f '{{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} drop={{.HostConfig.CapDrop}} add={{.HostConfig.CapAdd}} sec={{.HostConfig.SecurityOpt}} init={{.HostConfig.Init}} restart={{.HostConfig.RestartPolicy.Name}} mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}}' "$GUARD")
ci=$(docker inspect -f '{{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} drop={{.HostConfig.CapDrop}} add={{.HostConfig.CapAdd}} sec={{.HostConfig.SecurityOpt}} restart={{.HostConfig.RestartPolicy.Name}} mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}} sysctls={{.HostConfig.Sysctls}}' "$CADDY")
note "guard: $gi"
note "caddy: $ci"
echo "$gi" | grep -q '^10001:10001 ro=true drop=\[ALL\] add=\[\] sec=\[no-new-privileges:true\]' && ok "the guard: user 10001, read-only, every capability dropped, no new privileges" || bad "the guard runs as: $gi"
echo "$ci" | grep -q '^10002:10002 ro=true drop=\[ALL\] add=\[\] sec=\[no-new-privileges:true\]' && ok "Caddy: user 10002, read-only, every capability dropped, no new privileges, on 80 and 443" || bad "Caddy runs as: $ci"
note "the guard's processes (user id as the server sees it, and command):"
docker top "$GUARD" 2>/dev/null | awk 'NR > 1 { $2 = $3 = $4 = $5 = $6 = $7 = ""; print }' | sed 's/^/   | /'
[ "$(docker top "$GUARD" 2>/dev/null | awk 'NR > 1 && $1 != "10001"' | wc -l)" = "0" ] && ok "every process of the guard's container runs as 10001" || bad "a process of the guard's runs as another user"

# --- the files, in the bind-mounted folders ---
echo "-- guard-data, as the server sees it (owner, mode, name):"
( cd "$WORK" && find guard-data caddy-data caddy-config -maxdepth 2 -exec stat -c '%u:%g %a %n' {} + | sort -k3 | sed 's/^/   | /' )
listed=$(cd "$WORK" && find guard-data -exec stat -c '%u:%g %a %F %n' {} +)
wrong=$(echo "$listed" | awk '$1 != "10001:10001"')
[ -z "$wrong" ] && ok "every file in guard-data is the guard's user's (10001:10001)" || bad "not the guard's: $wrong"
open=$(echo "$listed" | awk '!(($3 == "regular" && $2 == "600") || ($3 == "directory" && $2 == "700"))')
[ -z "$open" ] && ok "nothing in guard-data can be read by anyone but the guard's user (files 600, folders 700)" || bad "readable by others, or not a file or folder: $open"
for f in executor-http.json permission-entries.json owner-link.txt oauth-state.json keys/executor.jwk keys/connection-1.jwk slips/connection-1.json demo-token; do
  [ -f "$WORK/guard-data/$f" ] || bad "guard-data/$f is not there"
done
[ "$(stat -c '%u:%g %a' "$WORK/caddy-data")" = "10002:10002 700" ] && [ "$(stat -c '%u:%g %a' "$WORK/caddy-config")" = "10002:10002 700" ] && ok "caddy-data and caddy-config are Caddy's user's, mode 700" || bad "Caddy's folders: $(stat -c '%u:%g %a %n' "$WORK/caddy-data" "$WORK/caddy-config")"
grep -q "^https://$DOMAIN/oauth/owner#" "$WORK/guard-data/owner-link.txt" && ok "the owner's link is in guard-data/owner-link.txt" || bad "owner-link.txt: $(cat "$WORK/guard-data/owner-link.txt")"
dc logs guard 2>/dev/null | grep -q '/oauth/owner#' && bad "the owner's link is in the guard's log" || ok "the owner's link is not in the guard's log"

# --- another command, through the start program, with the settings put in ---
if dc run --rm --no-deps -T guard check > "$WORK/check.txt" 2>&1; then ok "docker compose run --rm guard check: no problem"; else bad "docker compose run --rm guard check: $(tail -n 5 "$WORK/check.txt")"; fi

# --- the owner's command: refused while the guard runs, taken once it is stopped ---
or=$(dc run --rm --no-deps -T guard owner 2>&1)
if [ $? -ne 0 ]; then ok "owner, with the guard running, is refused"; else bad "owner ran beside a running guard"; fi
note "$(echo "$or" | tail -n 1)"
before=$(cat "$WORK/guard-data/owner-link.txt")
dc stop guard >/dev/null 2>&1
rr=$(dc run --rm --no-deps -T guard owner --reset 2>&1)
if [ $? -eq 0 ] && echo "$rr" | grep -q 'The owner was removed' && ! echo "$rr" | grep -q '/oauth/owner#' && [ "$(cat "$WORK/guard-data/owner-link.txt")" != "$before" ]; then
  ok "owner --reset, with the guard stopped: done, a new link written to the file, none printed"
else bad "owner --reset: $rr"; fi
echo "$rr" | sed 's/^/   | /'
after=$(cat "$WORK/guard-data/owner-link.txt")
dc start guard >/dev/null 2>&1
sleep 5
if wait_log 'still works' 60 && [ "$(cat "$WORK/guard-data/owner-link.txt")" = "$after" ]; then ok "the next start keeps the link that still works"; else bad "the start did not keep the link"; fi
code=$(curlc -o /dev/null -w '%{http_code}' -X POST "https://$DOMAIN/mcp")
[ "$code" = "401" ] && ok "after the restart, the guard answers through Caddy" || bad "after the restart: $code"

# --- Caddy restarted on its own: the guard, left in Caddy's old network, stops, and Docker starts it again in the new one ---
began=$(date +%s)
dc restart caddy >/dev/null 2>&1
sleep 3
CADDY_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$(dc ps -q caddy)")
code=$(curlc -o /dev/null -w '%{http_code}' -X POST "https://$DOMAIN/mcp" 2>/dev/null)
note "just after 'docker compose restart caddy' alone, POST /mcp through Caddy answered: $code"
while [ $(($(date +%s) - began)) -lt 180 ]; do
  code=$(curlc -o /dev/null -w '%{http_code}' -X POST "https://$DOMAIN/mcp" 2>/dev/null)
  [ "$code" = "401" ] && break
  sleep 2
done
[ "$code" = "401" ] && ok "after Caddy was restarted on its own, the guard answered through it again, $(($(date +%s) - began)) seconds after the restart began" || bad "after Caddy was restarted on its own, POST /mcp answered $code for 180 seconds"
note "the guard's restarts: $(docker inspect -f '{{.RestartCount}}' "$GUARD")"
dc logs --no-log-prefix guard 2>/dev/null | grep -F "has not answered in this network" | tail -n 1 | sed 's/^/   | /'

echo "-- the guard's last log lines:"
dc logs --no-log-prefix --tail 8 guard 2>/dev/null | sed 's/^/   | /'

cleanup
echo "passed $passed, failed $failed"
[ "$failed" -eq 0 ]
