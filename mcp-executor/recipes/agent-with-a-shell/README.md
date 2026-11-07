# An agent with a shell, kept from the tool server's credential

An agent with a shell or file tools can read every file its computer user
can read. So a guard that runs as the same user cannot keep the tool
server's credential from it. This example puts the guard in a container of its own, apart from the
agent's container, so that the agent's shell cannot read the guard's
files. The agent's container can reach the guard but not the tool server.
The guard holds the credential; the agent holds only its own secret.
Anyone who can run Docker commands on that computer, a person or an
agent, can read the guard's files and the credential with them. So the
agent must not run as a computer user who can use Docker.

It has been run with Docker Desktop on Windows, on one computer. It has
not been tried on separate computers.

## What runs where

| Container | Network | Holds |
|---|---|---|
| `provared-example-agent` | the agent's network | a shell (root in its own container), its own secret, and the certificate of the guard's proxy |
| `provared-example-guard` | both networks | `provared-mcp-executor` 0.3.0 from npm, listening on 127.0.0.1; its keys, the permission, the book and the copy; the tool server's token; a TLS proxy on port 8443 |
| `provared-example-tools-server` | the tools network only, which has no route out (`--internal`) | a stand-in tool server that asks for the token |

The guard speaks plain HTTP, so something else must encrypt the link to
it. Here that is a small Node.js TLS proxy (`proxy.mjs`), with a
certificate made at each run. The link from the guard to the tool server
is plain HTTP on the closed network, and the guard warns about it when it
starts. A tool server reached over any other network should be reached by
HTTPS.

## Run it

On a computer with Docker, the image `node:24` and access to npm, from
this folder:

```
sh run.sh
```

It takes a few minutes, prints seven checks, and then removes its
containers and networks, also after a failure. Before it starts, it stops and removes any container named
`provared-example-agent`, `provared-example-guard` or
`provared-example-tools-server`, and any network named
`provared-example-agent` or `provared-example-tools`, with whatever they
hold. Do not run it where those names are in use.

## The seven checks

1. The agent reaches the guard over TLS 1.3 and accepts its certificate.
2. An allowed call runs; a refused call never reaches the tool server.
3. The agent's book, which the guard writes and keeps, shows no problem,
   and the guard's copy agrees with it.
4. From a shell in the agent's container: no text file, environment variable or process's environment holds the token; the tool server's
   name does not resolve; the guard's plain port refuses connections.
5. The token is in nothing the agent received, and not in the guard's
   log, book or copy.
6. Without the certificate, the agent's connection fails and the tool
   server sees nothing more.
7. A request with an unknown `Origin` gets 403, and a wrong secret 401.

All seven passed on 7 November 2026, with the official MCP software
(`@modelcontextprotocol/sdk` 1.32.2) on protocol version 2025-11-25.

## What it does not show

- **Separate computers.** These are three containers on one computer,
  kept apart by Docker's networks.
- **A real passkey.** The permission is signed with the library's
  development stand-in for a passkey (`guard-setup.mjs`). In real use a
  person signs it with their passkey.
- **An agent that can control Docker,** or sign in where the guard runs:
  it could read the guard's files, and the credential with them.
- **A tool that returns the token in another form.** The guard removes
  only the token's exact text from what it sends an agent.
- **The token in another form.** Checks 4 and 5 search for the start
  that every token in this example has, as the agent never had its full
  value. That also finds the whole token, but not one that is encoded,
  split or in a binary file.
- **A hardened proxy.** `proxy.mjs` asks for no client certificate;
  agents sign in with the guard's own secrets.
- **The agent's shell.** The guard sees and records only the calls that
  pass through it to the tool server, not what the agent does in its
  shell.

The guard's record shows what passed through the guard. It proves
nothing about a tool the agent can reach another way. Evidence, not a
verdict.
