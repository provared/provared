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

`server.mjs` and `content-rules.json` are also used by the command
`provared-mcp-executor demo` (the file `demo.mjs` one folder up), which
runs once in a new temporary folder and ends; those two files are in the
npm package, and the rest of this folder is not.

- `server.mjs`: a made-up tool server over stdio, with no dependencies. It
  has two harmless tools: `echo` hands back a text, and `add` adds two
  whole numbers. It reaches no network. It will not start unless
  `DEMO_TOKEN` equals the made-up credential in the file `demo-token` of
  the folder it is started in, which the executor reads and passes on; the
  agent's client is never handed it. That shows where a credential lives;
  it is not a protection, since anything that can read the folder can read
  the file.
- `content-rules.json`: one rule on content, so that a refusal can be
  seen: `echo` is refused for any text that holds the lower-case word
  `password`. Patterns compare characters exactly, so `PASSWORD` passes.
- `start.mjs`: the start. It keeps everything in the folder
  `PROVARED_DEMO_DIR` (by default `.provared-mcp-demo` in the home
  folder), and uses that folder only if it is empty or holds the
  demonstration's own mark, `provared-demo.json`; any other folder is
  refused and left untouched. Each set-up is a folder of its own inside it
  (`set-up-…`), and the mark names the one in use. A set-up holds a
  development stand-in for a passkey's thumbprint, the executor's settings,
  the made-up credential, the agent's and the executor's keys (made with
  the executor's own `keys` command), and a permission for `echo` and
  `add`, valid for 30 days and signed with the stand-in; the executor's own
  `check` then reads it. On every start the paths to Node.js, to
  `server.mjs` and to the rules file are written into the settings afresh,
  so the demonstration still starts after it is moved, or after Node.js is
  upgraded, and the settings are checked again. A set-up whose permission
  has ended, ends within the hour, cannot be read, or no longer passes the
  check is not used: it is left where it is (with at most its paths
  written afresh), and a new one is made beside it; the start says why. Then it starts `provared-mcp-executor stdio` on its own input and
  output. What it says goes to its standard error.
- `package.json`: the two packages from npm, at exact versions:
  `provared` 0.7.0 and `provared-mcp-executor` 0.2.0. Neither has any
  other dependency. To try a copy of the executor that is not published,
  build the `Dockerfile` with a packed copy, as it says.
- `Dockerfile`: the same, in a container; `Dockerfile.dockerignore` sends
  the builder only the four files it needs.

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

The demonstration needs a folder it can write. A container started with
`--read-only` stops with a message that says so; give it a place to write
with `--tmpfs /home/node/provared-demo`, or a volume there.

Run one start at a time on one folder: two starts at once on an empty
folder each make a set-up of their own, but two starts at once on a
folder already set up share its book, and once the first has written to
it the second takes no more calls ("the book file is not as the executor
left it").

It speaks MCP on its standard input and output. An MCP client sees two
tools, `echo` and `add`. A call to either is checked against the
permission, sent to the made-up server, and given a receipt that the
executor countersigns; `echo` with a text that holds the word `password`
is refused, and a denial is written. The book is `book.jsonl` in the
set-up's folder; check it with the trusted passkey's thumbprint, which its
settings name:

```
npx provared-check --issuer <the thumbprint in executor.json> <set-up folder>/book.jsonl
```

The checker shows the issuer's name with "(development)" in it.

## For a directory that builds from the repository

A service that clones the repository, installs, and starts a command from
the top folder can use:

- Node.js: 24
- build step: `npm install --prefix mcp-executor/demo --omit=dev --ignore-scripts --no-audit --no-fund`
- command: `node mcp-executor/demo/start.mjs`

No setting and no secret is needed: the start makes everything it uses.
