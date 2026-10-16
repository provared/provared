# <img src="https://prova.red/favicon.svg" alt="" width="36"> provared-hermes

A Hermes Agent plugin that checks each tool call of the agent against the
permission a person signed, runs the call only if the permission allows
it, and records it with [Provared](https://github.com/provared/provared).

*Evidence, not a verdict.*

**Version 0.1.0, a draft**, as Provared itself is, by one author in their
own time; fixes as time allows. It is not on the Python Package Index
yet: see "Install" below.

## What it does

Provared is a way to prove what an AI agent was allowed to do, and what
it then did. A person signs a **slip** with a passkey: which agent, which
actions, which limits, until when. Beside the agent, Provared's stub
writer checks each action against the slip before it is taken and, if it
is allowed, writes a signed **stub** for it into a book that anyone can
check later.

This plugin puts every tool call of a Hermes agent behind that stub
writer:

- **Allowed:** the tool runs, and a stub is written. The stub names the
  action, the tool, and the SHA-256 fingerprint of the arguments the tool
  received, so the record fixes exactly what was asked for without
  holding it. It is dated when the call started.
- **Not allowed** (an action the slip does not name, over a limit, after
  the slip ends or was cancelled): the tool is not run, nothing is
  written, and Hermes hands the model a failed tool answer that says why,
  for example: `The tool "send_message" was not run. The slip does not
  allow the action "provared.message.send".`
- **Failed:** a call that reached the tool and came back with Hermes's
  error answer, or whose tool raised an error, is recorded too, because
  it may have done part of its work: the stub names the tool as failed,
  with the fingerprint of the error. A raised error then goes on to
  Hermes as before.
- **Stopped by Hermes itself** after the check (another plugin's veto, a
  guardrail, an approval a plugin asked for that the person refused): not
  run, and no stub. A terminal command that Hermes's terminal tool itself
  asks the person about, and the person refuses, reached the tool, and is
  recorded as failed.

Each tool call is named by the plugin, never by the agent, with a name
from the format's shared list: reading a file is `provared.data.read`,
writing one `provared.data.change`, a web search `provared.web.read`, a
subagent `provared.agent.instruct`, a terminal command `provared.code.run`
(or `provared.data.delete` for a command that removes something, and
`provared.code.release` for one that publishes). A tool the plugin does
not know, an MCP tool or a connector included, is named
`provared.code.run`, the widest name, so a new tool is checked rather
than let through. A question to the person, the model's own list of tasks
and the catalogue of tools are not recorded. The full list is in
[`src/provared_hermes/actions.py`](src/provared_hermes/actions.py).

### How a terminal command is named

A command is named from its text, by three readings, and the strictest
name any of them finds counts. They are those of the recorder beside
Claude Code in this repository, by the same rules, and the tests of both
hold the same rows, so that the two name a command alike
([`src/provared_hermes/commands.py`](src/provared_hermes/commands.py)):

- The command line read roughly as a shell reads it: quotation marks
  taken off, comments left out, and `;` `&` `|` `(` `)` and line breaks
  starting a new command (`2>&1`, `>&2` and `&>` are redirections, not
  breaks). A program is known by its name in any letter case, without
  its folder or its ending (`/bin/rm`, `\rm`, `rm.exe`), after settings,
  redirections and wrappers such as `sudo`, `env`, `timeout` or
  `command`. A command line handed on is read the same way: to a shell
  (`bash -c`, `cmd /c`, `powershell -Command`), to `eval`, `iex` or
  `Invoke-Expression`, to `ssh` (the words after its destination), to
  `watch` and `parallel`, each command `find -exec` runs, and a value in
  quotation marks after `-c`, `--command`, `-Command` or `-ArgumentList`
  (`su -c "..."`, `Start-Process cmd -ArgumentList '/c ...'`) or after
  `env -S`, unless it is handed to a program that only searches or shows
  text, to `git`, to `ssh` or to an interpreter. This reading also finds
  a script's own calls that delete (`shutil.rmtree`, `os.remove`,
  `fs.rmSync`, `Path(...).unlink()`, `File.Delete` and the like) in a
  command line that runs an interpreter (Python, Node.js, Ruby, Perl,
  PHP, Deno, Bun, PowerShell), a script written into the line after it
  (`python - <<EOF`) included, and reads again the strings of a script
  that hands a command line to the system (`subprocess`, `os.system`); a
  move to the null device (`mv x /dev/null`); and a file emptied by a
  redirection alone (`: > file`).
- In each command, every later word that names a known program or an
  interpreter is read as the start of a command, whatever stands before
  it (`docker exec web rm`, `npx npm publish`), and a later shell,
  `eval`, `ssh`, `watch` or `parallel` has its line read as above
  (`docker exec web sh -c "..."`). A word written as a program's path
  counts (`docker exec web /bin/rm`), but not a word with `/` or `\`
  inside it (a path to a file, a web address). A word in quotation marks
  counts only after a program that runs another one (`docker exec web
  "rm"`), not after one that only searches or shows text
  (`sudo grep -w "rm"`). A commit message after `-m` (after `git`, `hg`,
  `docker` and the like) or `--message` does not count: so
  `git commit -m "Remove the rm calls"` is a run.
- The patterns of that recorder's first version, as they were, in the
  text outside quotation marks.

Deletions: `rm`, `rmdir`, `rd`, `del`, `erase`, `ri`, `Remove-Item`,
`Clear-Content`, `unlink`, `truncate`, `shred`; `find` with `-delete` or
`-exec rm`; `npm unpublish`; `gh repo delete`, `gh release delete`, `gh api`
with the method DELETE; in git, with any of git's own options before the
command (`git -C dir`, `git -c name=value`): `rm` (not `--cached`), a push
that is forced, deletes, mirrors or prunes, `reset --hard`, `clean` (not
`-n`), `branch` or `tag` with `-d`, `stash drop` and `clear`,
`checkout --force` or `checkout -- <paths>`, `restore`; `DROP TABLE` or
`DROP DATABASE` anywhere in the text; `DELETE FROM` given to a database
client (`psql`, `mysql`, `sqlite3` and a few more); `redis-cli FLUSHALL`
or `FLUSHDB`; `rsync --delete`; `cp /dev/null x`; `gem yank`,
`cargo yank`, `dotnet nuget delete`. Releases: `git push` (and
`hub push`), `npm publish` (and pnpm, yarn, bun), `twine upload`,
`publish` given to `uv`, `poetry`, `cargo`, `hatch`, `flit`, `pdm`,
`vsce` or `ovsx`, `gem push`, `helm push`, `dotnet nuget push`,
`docker push`, `docker build` or `buildx` with `--push`,
`gh release create`, `upload` or `edit`, `gh repo edit`, `gh pr create`
and `merge`. Also read, one level down: each `$( ... )` and `` `...` ``
inside `"..."` (`echo "$(rm -rf x)"`), but not inside `'...'`, nested to
any depth: a quotation mark inside a `$( ... )` does not end the `"..."`
(`echo "$(cd "/tmp"; rm -rf x)"`), nor does the `)` of a `case` pattern
end the `$( ... )` (`echo "$(case x in a) rm -rf y;; esac)"`), nor a `)`
in a `#` comment there, and a `\$` or `` \` `` written in
`"..."` is plain text (`grep -rn "\$(rm" docs`); what a
command writes into a shell given nothing but options after a single
`|` (`echo "rm -rf x" | sh`); a here-string (`bash <<< "..."`); and
`-ArgumentList` written as a list (`"/c","del x"`).

This is a reading of the command's text, and it can always be got round:
a script that deletes in a way not listed here or from a file, a program
renamed or copied, a name built in a variable, an upload with `curl` or
`scp`. Known gaps, as of 16 October 2026, the same as the recorder
beside Claude Code's: a command line in a file (`pwsh -File clean.ps1`,
`sh script.sh`) or in a variable (`x=rm; $x -rf y`); PowerShell's
`-EncodedCommand`; text piped into a shell that is also given a script
or other words, or from a file (`cat cmds.txt | sh`); a program's name
written in escaped quotation marks inside a quoted line
(`bash -c "\"rm\" -rf x"`), because `\"` inside `"..."` is not read as an
escape, so that a Windows folder written `"C:\x\"` ends its quotation
where cmd ends it, and the same holds for a quotation inside a
`$( ... )` (`echo "$(echo "\")\"" ; rm x)"` is a run); SQL other than
`DROP` and `DELETE FROM`
(`TRUNCATE TABLE`, `UPDATE`); publishing tools not listed above; and a
request that deletes or publishes through an API, such as
`curl -X DELETE`. So a
permission's `never: destroys` stops only the commands that read as
deletions, and the record's kind of action is the plugin's reading of the
call, not a fact about it. A word that names a deletion counts even where
a shell would not run it (`echo rm`): the reading errs towards the
stricter name, though not inside a quoted message, a path or a web
address.

## Install

You need Hermes Agent 0.21.7, or a later 0.21 version, with plugins run
in Hermes's own process: the setting `plugins.isolation: in_process`,
which is the default. In Hermes's plugin host
(`plugins.isolation: host`) the plugin cannot hand a call on to its tool,
so it runs no recorded tool call at all; and if the plugin host process
itself ends (any plugin in it failing), Hermes runs the tools with no
check, which no plugin in the host can prevent.

The plugin was tested with Hermes 0.21.7. Its manifest names no version
of Hermes at all, neither a lowest nor a highest, because Hermes skips a
plugin whose manifest rejects the version running, and its tools would
then run with no check at all. So the plugin always loads, and checks the
version itself. On a Hermes older than 0.21.7 (0.21.6 and before), on
0.22 and after, or on one whose version cannot be read, it runs no
recorded tool call, and the model is told why, until you set
`untested_hermes: run` (below). On 0.21.7 and later 0.21 versions it
works as described here.

The plugin needs `provared` 0.4.0 or later, before 0.6 (it is tested
with 0.4.0 and 0.5.0), from the Python Package Index. The plugin itself
is **not on the Python Package Index yet**: install it from this
repository, into the Python environment Hermes runs in (you need git):

```
pip install "provared-hermes @ git+https://github.com/provared/provared#subdirectory=python/integrations/provared-hermes"
hermes plugins enable provared
```

Once it is on the Python Package Index, the first line will be
`pip install provared-hermes`.

Or copy this folder into `~/.hermes/plugins/provared` (on Windows,
`%LOCALAPPDATA%\hermes\plugins\provared`) and enable it; Hermes asks
before it installs `provared`.

## Use

```
hermes provared init
```

This makes the agent's two keys (Ed25519 and ML-DSA-87) and prints a link
that opens the signing page at prova.red with a starting permission
filled in, naming those keys. Change the permission there if you wish,
sign it with your passkey, and put the saved file in place:

```
hermes provared use slip.json
hermes provared status
```

From then on every tool call of the agent is checked and recorded. When a
permission ends, sign a new one the same way: Hermes takes it in at its
next tool call, once the calls running then have ended (meanwhile no
recorded call is run). With the package installed by pip, the same
commands also run as `python -m provared_hermes <command>`.

The plugin takes a permission only from a passkey on its list,
`trusted-passkeys.json` in its folder: the first `use` writes it, with that
permission's passkey, and only `use <file> --new-passkey` adds to it. A
permission signed by any other passkey is refused, whether it is handed to
`use` or put in place by hand, and the plugin runs no recorded call while
its book, or `slip.json`, holds one. This raises the bar; it does not close
the gap: see "What to know". `hermes provared status` checks the book
against the passkeys on the list, never against those the book names
itself.

### Stopping the agent

- **Take the permission away:** a missing, empty or unreadable `slip.json`
  is no permission. From the next tool call, no recorded call is run.
- **Cancel it, in the record:** sign a cancellation of the permission on
  the signing page, then put the file it saves in place:

  ```
  hermes provared cancel cancellation.json
  ```

  At its next tool call Hermes writes the cancellation into the book, with
  the agent's signed acknowledgement that it was handed it, and acts no
  more under the permission it cancels. A cancellation that does not pass
  its check stops every recorded call until it is put right or taken
  away.

A permission put back after a later one (an earlier `slip-<fingerprint>.json`
copied over `slip.json`) is not taken: `slip.json` must be the latest
permission of the book, or a new one. To go back to wider terms, sign a new
permission.

To check the book on any device, with the passkey you trust:

```
npx provared-check book.jsonl --issuer <the thumbprint of your passkey>
```

### The folder

The plugin keeps its files in Hermes's data folder for it,
`<Hermes home>/plugin-data/provared`, which follows the active profile:
each profile is an agent of its own, with its own keys and book.

| File | What it holds |
|---|---|
| `agent-keys.jwk` | the agent's two private keys. Never share this file. |
| `trusted-passkeys.json` | the thumbprints of the passkeys whose permissions the plugin takes |
| `slip.json` | the signed permission the agent acts under |
| `slip-<fingerprint>.json` | each permission of the book that stood in its place before |
| `cancellation.json` | a signed cancellation, where one was put in place |
| `book.jsonl` | the book: the permissions and a stub for each tool call |
| `book.lock` | held by the one Hermes process that writes to the book |

### Settings

In Hermes's `config.yaml`, under `plugins.entries.provared.settings`:

- `folder`: another folder for the files above.
- `actions`: your own action names for some tools, by tool name, for
  example `send_message: provared.message.send`. They cannot stop a tool
  from being recorded.
- `unknown_chain`: what to do where the plugin cannot read Hermes's chain
  of middleware (below): `refuse` (the default) or `run`.
- `untested_hermes`: what to do on a Hermes that is not 0.21.7 or a later
  0.21 version, older or newer (above): `refuse` (the default) or `run`.
  With `run`, the plugin goes on and says so in Hermes's log.

A mistake in the settings stops every recorded tool call, and the model
is told why, rather than leaving Hermes without the plugin.

## What to know

- **The check sits in Hermes's `tool_execution` middleware.** It must be
  the last such middleware, the one next to the tool, so that no other
  plugin can change the call after the check or answer in the tool's
  place. Where another plugin's middleware comes after it (Hermes loads
  plugins in the order of their names), no recorded call is run, and the
  model is told why. The plugin tells by reading how Hermes 0.21 builds
  its chain; where it cannot read it, it runs no recorded call, unless
  the setting `unknown_chain` is `run`. On a Hermes later than the 0.21
  versions it runs no recorded call at all unless `untested_hermes` is
  `run` (see "Install").
- **Nothing it does before the tool can let the tool through.** Hermes
  runs the tool anyway when a middleware fails before passing the call
  on, so every fault there is turned into a refusal.
- **Hermes runs its own checks after Provared's.** In the agent's own
  loop, Hermes runs every plugin's `pre_tool_call` hooks, its guardrails
  and its approval prompts inside the middleware, after the check. A call
  they stop leaves no stub. A hook that rewrites the arguments
  (`modify`) does so after the check: the call was checked with the
  arguments before the change, and the stub names the arguments the tool
  received, as Hermes reports them, so a checker shows any breach.
  Hermes reports them before the call returns for its registry's tools;
  for a few tools that run inside the agent (memory, session search,
  subagents and some others) only afterwards, and then the plugin can
  only warn that the stub names other arguments. Hermes's report of a call
  it gave up waiting for, or stopped, is not used: it holds the arguments
  as the model gave them.
- **A call made from inside another** (by `execute_code`'s sandbox, a
  subagent, or the entries of a batch of connector calls) is checked and
  recorded as itself, under the same permission, and the outer call is
  recorded when it ends. A subagent's tool calls are recorded as the
  agent's own: Provared's passes for helper agents are not used here.
- **Hermes passes over one call twice in one of its paths**
  (`AIAgent._invoke_tool` with its defaults runs the middleware around a
  call and again inside it). The inner pass is taken for the same call
  only in the same thread, once, with the same arguments; any other call
  with the same tool and the same call identifier (two subagents whose
  model service numbers its calls alike) is checked and recorded as a call
  of its own, and Hermes's reports are matched to the call running in
  their own context.
- **Calls side by side.** Hermes runs some calls at the same time (reads,
  searches, writes to different files, the desktop app's terminal
  commands, subagents). Where the permission limits how many of an action
  may be taken, a call is run only while the stubs already in the period,
  the calls of that action still running and this one together fit;
  otherwise it is not run, and the model is told to make it again once
  the others have ended. Calls of actions with no such limit run side by
  side as before.
- **One Hermes process writes to a book.** A second one on the same
  profile (the gateway beside a terminal session, a worker) finds the
  book held, records nothing, and runs no recorded call. If the book file
  is changed by another program, the plugin writes nothing over it and
  runs no recorded call until Hermes is started again.
- **When Hermes unloads the plugin** (it is disabled, or Hermes discovers
  its plugins again), a call still running keeps its writer and the book:
  its stub is written when it ends, and only then is the book let go. The
  plugin loaded again meanwhile finds the book held, and runs none of its
  recorded calls until then. Hermes removes the plugin's middleware when
  it unloads it, and adds it again when it loads it: a tool call that
  starts in between runs with no check and leaves no stub. That gap is
  Hermes's own, and the plugin cannot close it.
- **Nothing on the computer is out of the agent's reach.** The agent runs
  as you, and can run commands: any program on the computer, the agent
  included, can change the files in the plugin's folder (the list of
  trusted passkeys among them), run `use --new-passkey`, or switch the
  plugin off in Hermes's settings. The list of trusted passkeys raises the
  bar; it does not close the gap. The evidence that holds is a checker
  that names your own passkey (`provared-check --issuer`): a permission
  signed by any other passkey is then reported as a problem in the
  record.
- **Not sealed.** The Python version of Provared cannot make the third
  signature of a seal (SLH-DSA), so this plugin writes no seals; seal the
  book with the JavaScript library if you need one.
- **What it covers:** the tool calls that pass through Hermes's
  middleware. A tool that the model's own service runs on its side, a
  shell hook, or work a tool does without calling another tool is part
  of that one call's stub, not recorded one by one. If Hermes cannot load
  the plugin, it runs without it: `hermes plugins list` shows whether it
  is loaded.
- **A fingerprint can be guessed** where the arguments are few and easy
  to guess, such as one short name.
- **What the record shows, and what it does not,** is set out in
  Provared's README and its
  [list of threats](https://github.com/provared/provared/blob/main/docs/threat-model.md).
  In short: it shows what was recorded under a slip the person signed,
  not what was left out, and not whether an action was wise or lawful.
  Every stub is one-sided: no other party countersigns a tool call.

Nothing here reaches the network, and nothing is reported anywhere.

## Hermes's plugin catalogue

The plugin is not listed in Hermes's catalogue yet. A draft of its entry,
for the owner of this repository to submit, is
[`catalog-entry.yaml`](catalog-entry.yaml). Hermes's own admission check,
`hermes plugins validate`, passes on this folder.

## Tests

`tests/test_recorder.py` drives the plugin's recorder directly, as
Hermes's middleware chain calls it. `tests/test_plugin.py` runs a real
Hermes agent with Hermes's own stand-in model, a server inside the test
program that answers with replies scripted in advance, so no AI service
is called; a guard refuses any connection outside the program and the
start of any other program while they run (one test lets Hermes start its
own plugin host, a local Python process, and still refuses every
connection). They need a copy of this repository (they use the guard in
`python/examples/`) and an environment that holds Hermes's source, which
its stand-in model is part of. On Python 3.14, from this folder:

```
python -m venv .venv
.venv/Scripts/python -m pip install -e <a checkout of Hermes Agent at v0.21.7>
.venv/Scripts/python -m pip install -e ../..
.venv/Scripts/python -m unittest discover -s tests
```

## Licences

As for the rest of the repository: the Apache License 2.0 for the code,
and Creative Commons Attribution 4.0 for this page.
