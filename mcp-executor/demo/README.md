# A demonstration of the executor

**This is a demonstration only.** Its permission is signed by the Provared
library's development stand-in for a passkey (`provared/dev`), not by a
person: the issuer's name ends with "(development)", the stand-in is made
for one set-up and then forgotten, and the records it leaves prove nothing
about anyone. Do not use this folder for real work: for that, follow "Set
it up" in the executor's own README, where a person signs the permission
with their own passkey.

It runs `provared-mcp-executor` in front of a made-up MCP tool server, so
that the executor can be started and looked at, for example by a directory
of MCP servers that starts each server and asks it what it offers.

## What is in it

- `server.mjs`: a made-up tool server over stdio, with no dependencies. It
  has two harmless tools: `echo` hands back a text, and `add` adds two
  whole numbers. It reaches no network and touches no file. It will not
  start without a made-up credential, `DEMO_TOKEN`, which only the
  executor holds.
- `content-rules.json`: one rule on content, so that a refusal can be
  seen: `echo` is refused for any text that mentions a password.
- `start.mjs`: the start. On the first start it makes, in the folder
  `PROVARED_DEMO_DIR` (by default `.provared-mcp-demo` in the home
  folder), a development stand-in for a passkey, the executor's settings,
  the made-up credential, the agent's and the executor's keys (with the
  executor's own `keys` command), and a permission for `echo` and `add`,
  valid for 30 days and signed with the stand-in; then it runs the
  executor's own `check`. On a later start it uses what is there, unless
  the permission ends within the hour; then the folder is renamed aside
  and the set-up runs again. Then it starts `provared-mcp-executor stdio`
  on its own input and output. What it says goes to its standard error.
- `package.json`: the two packages from npm, at exact versions:
  `provared` 0.7.0 and `provared-mcp-executor` 0.2.0. Neither has any
  other dependency.
- `Dockerfile`: the same, in a container.

## Run it

With Node.js 24.7 or later, from this folder:

```
npm install --omit=dev --ignore-scripts
node start.mjs
```

Or in a container, from the top of the repository:

```
docker build -f mcp-executor/demo/Dockerfile -t provared-mcp-executor-demo .
docker run -i --rm provared-mcp-executor-demo
```

It speaks MCP on its standard input and output. An MCP client sees two
tools, `echo` and `add`. A call to either is checked against the
permission, sent to the made-up server, and given a receipt that the
executor countersigns; `echo` with a text that mentions a password is
refused, and a denial is written. The book is `book.jsonl` in the
demonstration's folder; check it with the trusted passkey's thumbprint,
which the settings name:

```
npx provared-check --issuer <the thumbprint in executor.json> <folder>/book.jsonl
```

The checker shows the issuer's name with "(development)" in it.

## For a directory that builds from the repository

A service that clones the repository, installs, and starts a command from
the top folder can use:

- Node.js: 24
- build step: `npm install --prefix mcp-executor/demo --omit=dev --ignore-scripts --no-audit --no-fund`
- command: `node mcp-executor/demo/start.mjs`

No setting and no secret is needed: the start makes everything it uses.
