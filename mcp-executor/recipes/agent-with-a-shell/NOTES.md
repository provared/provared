# Notes: an agent with a shell, behind the executor (guard) over TLS

Plain facts for whoever writes the page. Nothing here is published or sent; `run.sh` makes one outside fetch: `npm install` inside the guard container (`provared-mcp-executor@0.3.0`, and the SDK `@modelcontextprotocol/sdk@1.32.2`).

## Command

From this folder, on a computer with Docker, the image `node:24` and access to npm:

    sh run.sh

It works in Git Bash on Windows (it sets `MSYS_NO_PATHCONV=1`) and on Linux. Each wait has a limit (60 seconds); the client run and the checks have limits of 120 and 180 seconds. It ends with the seven results and removes the containers and networks by name, also after a failure (a `trap`).

## Files

- `run.sh`: the whole example. Makes networks `pv3-agent` and `pv3-tools` (`--internal`), containers `pv3-guard` (on both networks), `pv3-tools-server` (on `pv3-tools` only) and `pv3-agent` (on `pv3-agent` only). Installs the packages, runs the other files, judges the seven checks, cleans up.
- `guard-setup.mjs`: in the guard container. Makes executor and agent keys, a slip, the upstream token file, one agent secret (only its hash goes in the settings) and the settings. The slip is signed with the library's development stand-in for a passkey; a real slip is signed by a person with a passkey. It imports `files.mjs` and `http.mjs` of the package by file path, because the package `exports` do not list `files.mjs`.
- `guard-checkbook.mjs`: in the guard container. Reads the agent's book with the library (`checkBook`).
- `proxy.mjs`: in the guard container. TLS on 0.0.0.0:8443 to the guard on 127.0.0.1:8796. Not hardened; no client authentication.
- `tool-server.mjs`: a stand-in tool server (not a real one). Two tools, `allowed_tool` and `other_tool`; requires a bearer token; logs one line per request.
- `agent-client.mjs`: SDK client in the agent container. Reports the TLS version, lists and calls both tools, saves what it received.
- `agent-checks.sh`: runs in the agent container; searches for the token prefix, tests reachability, sends two probe requests (foreign `Origin`; wrong secret). Prints `CHK name=value` lines that `run.sh` reads.
- `package.json`: private; the SDK at exactly 1.32.2, for the stand-in server and client only.

## The seven checks (what each tests)

1. TLS 1.3 to the guard, certificate accepted (client's own handshake).
2. `allowed_tool` ran; `other_tool` was refused by the guard and the tool server log has no line for it.
3. The agent's book has no problem (`checkBook`), and `compare --agent alpha` says `agree: true`.
4. In the agent container: the token's known prefix is in no file, in `env` or in `/proc/*/environ`; the tool server's name does not resolve and the tool server is not reachable; the guard's plain port 8796 and port 9000 refuse connections. A control search finds the prefix in the guard's token file.
5. The prefix is not in what the client received, nor in the guard's log, book or copy.
6. With no certificate given to the client it fails (`DEPTH_ZERO_SELF_SIGNED_CERT`) and the tool server's request count does not change.
7. A request with `Origin: https://evil.example` gets 403; a wrong secret gets 401.

## Output of the final full run

Log: `D:\Users\Public\claude-scratch\temp\recipe-run.log`. Exit status 0. Results block:

    CHECK 1: PASSED - TLS 1.3 to the guard, certificate accepted
    CHECK 2: PASSED - allowed_tool ran; other_tool refused and never reached the tool server
    CHECK 3: PASSED - book has no problem; copy and book agree
    CHECK 4: PASSED - agent: token prefix in no file, env or /proc; tool server unreachable; plain port refused
    CHECK 5: PASSED - token prefix not in what the client received, nor in the guard's log, book or copy
    CHECK 6: PASSED - without the certificate the client fails; tool server request count stayed at 6
    CHECK 7: PASSED - foreign Origin gave 403; wrong secret gave 401
    0 check(s) failed

From the same run: `[tls] protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 authorized=true`; MCP protocol version negotiated 2025-11-25; book `lines 3 problemFound: false`, entries slip, stub (valid), denial; compare summary `sent 1, matched 1, differ 0, bookProblem false, agree true`. The guard printed two start-up warnings: the upstream URL is plain HTTP and not on this computer (here an internal Docker network), and `other_tool`'s action is not in the slip (intended). After the run, `docker ps -a --filter name=pv3-` and `docker network ls --filter name=pv3-` showed nothing.

## Differences from the trial (`RESULT.md` of the earlier run)

- Names `pv3-` instead of `pv2-`.
- No bind mounts: scripts, the certificate and the token are put in with `docker cp` or a pipe. The SDK is installed once in the guard container (the only one with a route out, the tool-server network being `--internal`) and copied to the other two by `tar`. So the trial's mounts listing prints nothing here. The trial used an SDK copy from an earlier folder.
- `--ignore-scripts` is used on the executor's install too (the trial did not).
- The agent secret is passed with `docker exec -e AGENT_SECRET` for each run, not set when the agent container was created. It is held in a shell variable on the host for the run and never printed.
- Secrets live in `/data` of the guard container (and the token in the tool server container); nothing is written to this folder or to a temporary folder on the host. They go when the containers are removed.
- Checks 3, 5 and 6 and the control search were done by hand in the trial; here `run.sh` does them. Check 7 here is only the `Origin` and wrong-secret probes; the trial's other findings under 7 (the guard did not refuse `listen.host: 0.0.0.0`; the `Host` header was not checked; two `tlsClientError` lines) are not re-tested.
- The tool server compares the bearer token with `timingSafeEqual` (the repository's lint objected to a plain comparison).
- Check 2 also needs the tool server log to hold no `other_tool` text at all.

## Not shown

- Two separate computers; real separation beyond Docker's networks; root in the agent container with the Docker socket (not given) was not tested.
- The token's full value was not searched for in the agent, only its known prefix. A tool that echoes or encodes the token was not tried.
- The guard-to-tool-server hop is plain HTTP (an internal Docker network). The proxy is not hardened. The agent's own secret is the only sign-in to the guard.
- The slip is signed with the development stand-in passkey, not a real passkey.
- Whether a tool did what its result says; calls that did not go through the guard.
- Run on Windows (Git Bash, Docker Desktop) only; not run on Linux.
