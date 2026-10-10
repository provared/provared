# Provared beside Claude Code

A coding agent, Claude Code, recorded by Provared: every tool call it
makes is checked against a permission the person signed with a passkey,
refused if it is outside it, and receipted if it is taken. The result is
a book that anyone can check with the free checker.

*Evidence, not a verdict.*

This folder names a product, as the framework packages in
`python/integrations/` do; the library itself names none. It is not part
of the npm package: run it from a copy of the repository. It needs
Node.js 24.7 or later and nothing else.

## How it works

Claude Code can run a small program before and after each tool call (its
"hooks"). The hook here, `hook.mjs`, names the call as an action from the
format's shared list (`actions.mjs`), fingerprints the call's arguments,
and asks a small service on this computer, `recorder.mjs`, which holds
the stub writer open on one book:

- **Before the call** (PreToolUse): the check before acting says whether
  the action is within the slip. If not, the call is refused and Claude
  Code is told why, in the checker's words. If the service is not
  running, the call is refused too: no record, no action.
- **After the call** (PostToolUse): a stub is written, signed with the
  agent's two keys, naming the tool and the SHA-256 fingerprint of its
  arguments. If it cannot be written, Claude Code is told, so that the
  gap is known.
- **Seals:** whoever runs the agent seals the book when they choose
  (`node recorder.mjs seal`), with the recorder's three keys. An outside
  time-stamp can be put beside a seal by hand; this recorder names no
  time-stamp service.

How tool calls are named, by the hook and not by the agent:

| Tools | Action |
|---|---|
| Read, Grep, Glob, LS, NotebookRead | `provared.code.read` |
| Edit, Write, MultiEdit, NotebookEdit | `provared.code.change` |
| WebFetch, WebSearch | `provared.web.read` |
| Agent, Task, Workflow (starting another agent) | `provared.agent.instruct` |
| Bash, PowerShell, and any MCP tool | `provared.code.run`, except: a command that removes something (`rm`, `Remove-Item`, `del`, `git reset --hard`, `git push --force`, `git clean`, …) is `provared.data.delete`, and one that publishes (`git push`, `npm publish`, `twine upload`, `gh release create`, …) is `provared.code.release` |
| A question to the person, a plan, a list of tasks, a skill | not recorded: they read and change nothing |

The stub holds the action, the time, the tool's name and the fingerprint
of its arguments: never the arguments themselves, and never a file's
contents. Whoever kept the transcript can show the arguments later, and
the fingerprint shows whether they are the ones the stub names.

## Setting it up

1. **Make the keys.** From the repository's folder:

   ```
   node integrations/claude-code/recorder.mjs keys
   ```

   It writes the agent's two private keys and the recorder's three to
   `~/.provared/claude-code/` (or the folder named by
   `PROVARED_CLAUDE_CODE_DIR`), and prints the agent's two public keys.

2. **Sign the slip.** Open https://prova.red/sign/ (or the same page from
   `npm run demo`, at `http://localhost:8787/page/sign.html`). Paste the
   public keys as `agent.keys`, write what the agent may do, and sign
   with your passkey. Save the file as `slip.json` in the folder above.
   Keep the passkey's thumbprint the page shows: a checker is told it
   with `--issuer`.

3. **Tell Claude Code to run the hook.** Copy the contents of
   `settings.example.json` into the project's `.claude/settings.local.json`
   (which git ignores) or your own `~/.claude/settings.json`. The
   SessionStart hook starts the recorder in the background if it is not
   running; or run it yourself and watch it:

   ```
   node integrations/claude-code/recorder.mjs start
   ```

4. **Work.** Each tool call is checked and recorded. A call outside the
   slip is refused, and Claude Code sees the reason.

5. **Seal and check.** Seal the book when you choose, and check it:

   ```
   node integrations/claude-code/recorder.mjs seal
   npx provared-check ~/.provared/claude-code/book.jsonl --issuer <the passkey's thumbprint> --sealer <the recorder's fingerprint>
   ```

   `node integrations/claude-code/recorder.mjs status` prints both
   fingerprints.

## What the record shows, and what it does not

- It shows every tool call that went through the hook, in order, signed
  by the agent's keys, with the person's signed permission as its first
  line, and whether each call was within it.
- It does not show a call that did not go through the hook: a tool not
  in the matcher, a session run with hooks switched off, or another
  program on this computer that asked the recorder to write a stub. The
  recorder listens on 127.0.0.1 and trusts any local caller; the record
  is of what this computer's agent did, as its own software says.
- Every stub is one-sided: there is no other party to countersign a tool
  call. The checker says so.
- A seal is signed by the recorder's keys, which live on the same
  computer as the agent's. Without an outside time-stamp beside it, the
  seal shows only that the book was whole when sealed, by the recorder's
  own word.
- The naming of a command (a deletion, a release, a run) is this hook's
  reading of its text. A command written to look harmless reads as a
  run.

## Tests

```
node --test integrations/claude-code/test/
```

The tests make a slip with the library's development stand-in for a
passkey, start the service on a free port, and run the hook as Claude
Code would, with its JSON on standard input.
