# Changelog of provared-gateway

## Unreleased

Version 0.1.0 has not been published. What it holds, as it stands:

- **The gateway's own countersignature.** A new setting, `gateway`
  (`keys`, the gateway's own key file of Ed25519 and ML-DSA-87; `name`;
  in a program, `privateKeys` and `keySet`). Where an agent's slip names
  that key set in the `with` entry of an upstream's service, the gateway
  countersigns each call of that agent to that upstream which it lets
  through, with the library's `countersign` (the countersignature of the
  format description, section 6; no new kind of record). It is made after
  the answer, over the stub that names the answer's or the error's
  fingerprint. A stub written when the administrator acknowledges a call is
  countersigned then, where the slip the call was sent under names the
  gateway's keys for its service. For that agent and service the upstream
  is not asked to countersign. The gateway does not start where a slip
  names the gateway's keys as the agent's. It warns, at start (a `warning`
  event in the log) and in `check`, where a slip names the gateway's keys
  for no service, where it does not require a countersignature for every
  action, where an upstream's calls are not countersigned by anyone, and
  where an upstream's `countersign` is not used. `check` lists the
  services each agent's calls are countersigned for. The `taken` event
  says whether the stub was countersigned; `status` gives `countersigner`
  and, for each agent, `countersigns` and `copy`. (`gateway.mjs`,
  `files.mjs`.)
- **The gateway's own copy** (`copy.mjs`). Where the gateway has its own
  keys, it keeps for each agent a copy apart from the book, in the form of
  the MCP executor's copy: numbered lines, each tagged with HMAC-SHA-256
  of the agent's name and the line under the agent's copy key, of the
  kinds `sending` (on the disk before the call is sent), `done`, `refused`,
  `set-aside` and `withdrawn`. New per-agent settings `copy` and `copyKey`
  (default `copies/<agent>.jsonl` and the same with `.key`). A copy line
  that cannot be written stops the agent (`503`, `agent-stopped`); the
  gateway does not start on a copy that has lines and no key, ends part-way
  through a line, has no line that checks, or is not whole. At a start, a
  call the copy shows as sent whose stub the book holds is noted `done`
  (`found-in-book`), and one with no line in the journal is noted
  `withdrawn`. Two agents may not share a copy or a copy key.
- **`provared-gateway compare`** (`compare.mjs`, exported as
  `provared-gateway/compare`): holds an agent's copy against its book, as
  the MCP executor's `compare` does, and ends with 0, 3 or 1.
- **`provared-gateway keys --gateway`** makes the gateway's key file and
  prints the slip's `with` entries that name its keys, with `"requires":
  [{"need": "countersignature"}]`. It refuses a path that is the recorder's
  or an agent's key file.
- **Getting ready to publish.** `package.json` lists `copy.mjs`,
  `compare.mjs` and `CHANGELOG.md` among its files, exports `./compare`, and
  asks for `provared` 0.9.0 exactly, as the MCP executor does (it asked for
  `>=0.9.0 <0.10.0`). The version stays 0.1.0. `gateway.example.json`
  names the gateway's own key file. The README says how to try the gateway,
  what the countersignature and the copy are and are not, and how
  `compare` reads.
- **Tests** (`test/countersign.test.mjs`, 10): the countersignature, its
  absence for other services, the copy's lines, refusals, the comparison
  (matched, missing, not in the copy, a changed line), the refusals at
  start, a copy that something else wrote to, a call never sent, `check`,
  and the commands `keys --gateway`, `acknowledge` after a stop without
  warning, and `compare`.
