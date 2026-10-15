# <img src="https://prova.red/favicon.svg" alt="" width="36"> provared-agno

An Agno tool hook that checks each tool call of an agent against the
permission a person signed, runs the tool only if the permission allows
it, and records the call with
[Provared](https://github.com/provared/provared).

*Evidence, not a verdict.*

**Version 0.1.0, a draft**, as Provared itself is, by one author in their
own time; fixes as time allows. It is not on the Python Package Index
yet: install it from this repository, as below.

## What it does

Provared is a way to prove what an AI agent was allowed to do, and what
it then did. A person signs a **slip** with a passkey: which agent, which
actions, which limits, until when. Beside the agent, Provared's stub
writer checks each action against the slip before it is taken and, if it
is allowed, writes a signed **stub** for it into a book that anyone can
check later.

`ProvaredToolHook` puts every tool call of an Agno agent behind that stub
writer:

- **Allowed:** the tool runs, and a stub is written. The stub names the
  action, the amount and the other party where they apply, and the
  SHA-256 fingerprint of the call's arguments, so the record fixes
  exactly what was asked for without holding it.
- **Not allowed** (over a limit, an action the slip does not name, after
  the slip ends or was cancelled): the tool is not run, nothing is
  written, and Agno hands the model a failed tool answer that says why,
  for example: `The tool "order_supplies" was not run. With this action
  the total would be 280 GBP. The slip's limit is 100 GBP: over by 180.`
- **A tool that is not described** to the hook is not run either, unless
  you pass `unlisted="run"`: the model is told, and Python gives a
  `RuntimeWarning`, so that a misspelt name shows.

## Install

```
pip install "provared-agno @ git+https://github.com/provared/provared#subdirectory=python/integrations/provared-agno"
```

You need Python 3.11 or later, and git. It installs `provared`, `agno`
and `pydantic`. Once the package is on the Python Package Index, this
will be `pip install provared-agno`.

## Use

```python
from agno.agent import Agent
from provared import open_recorder
from provared_agno import ProvaredToolHook

# The stub writer, on the book that holds the person's signed slip.
writer = open_recorder(book_text, slip_fingerprint, agent_private_keys, issuer_keys=[passkey_thumbprint])

hook = ProvaredToolHook(writer, {
    'order_supplies': {'action': 'supplies.order', 'with': 'supplier',
                       'amount': lambda args: {'unit': 'GBP', 'value': args['total_gbp']}},
    'send_message': 'provared.message.send',
})

# Its hooks, and no other tool hook.
agent = Agent(model=model, tools=[order_supplies, send_message], tool_hooks=hook.hooks)

agent.run('Order paper.')
book_text, held = writer.snapshot()   # keep both together
```

Name each tool as the model sees it. For each, give the action name the
slip uses for it, or a dict as for `provared.record_tools`, without
`run`: `action`, and where they apply `with`, `amount`, `details`,
`countersign` and `approve`. Each is checked when the hook is made, so a
mistake in a description, such as a misspelt member, shows when the
agent is built.
How to make a slip, a book and the agent's keys is in Provared's
[README](https://github.com/provared/provared/blob/main/README.md) and
[Python README](https://github.com/provared/provared/blob/main/python/README.md).

## What to know

- **Give the agent `tool_hooks=hook.hooks`, and no other tool hook.**
  They are two parts: Agno runs the first before the call and the second
  next to the tool. Another hook between them could change the call
  after the check, or answer in the tool's place. Given in any other way
  (another tool hook before or after, the hook alone, or on one tool
  only), no tool is run: each call is refused, the model is told why, and
  Python gives a `RuntimeWarning`. A team's own tools take the same, on
  the team.
- **It reads the call from the chain of hooks that Agno 3.1 builds**:
  the call itself, and what follows each part. If a later Agno builds
  its chain in another way, no tool is run, and the model and the
  developer are told why.
- **The tool is handed exactly what it would be handed without the
  hook,** and the record holds those values. The hook reads the call as
  Agno will make it: the defaults of the tool's parameters filled in, and
  each value converted by its type hint where Agno converts it (Agno
  converts nothing for a tool that takes the agent or the team). So
  `"30"` given for a whole number is recorded as `30`, and a parameter
  left out is recorded with its default. The values are written as JSON
  so that they read back as themselves: a secret (`SecretStr`) by its
  value; a model by the names it is read by, with every field, also one
  that pydantic leaves out when it writes JSON (`exclude=True`); a dict
  whose names are numbers (`Dict[int, int]`) with its names as text, as
  JSON writes them. That JSON form is what is fingerprinted and what the
  functions in a tool's description (`amount`, `with` and so on) are
  handed. A call whose arguments do not fit the tool is not run, and the
  model is told what is wrong. A value the person fills in when Agno
  asks them (`requires_user_input`) is checked and recorded with the
  rest.
- **A value with no JSON form.** A parameter left at a default of the
  tool's own that has no JSON form (an object of the program's, such as
  a client) is left out of the JSON form, and so of the fingerprint:
  read back, it takes that same default again, which is the very object
  the tool is handed. Any other value with no JSON form is refused,
  rather than changed: one given in the call, or one made afresh for
  each call (pydantic's `default_factory`), could not be fixed in the
  record, which could then not show what the tool was handed. A call
  whose values read differently a second time is refused for the same
  reason. Where Agno converts nothing (a tool that takes the agent or
  the team), a dict whose names are numbers is refused too: its JSON
  form, with names as text, would read back as another dict.
- **A change made before the check is checked and recorded.** A tool's
  own `pre_hook` runs before the tool hooks and may change the call; the
  call is checked as it then stands. With these hooks on the agent, Agno
  3.1 runs no tool hook that a tool sets on itself
  (`@tool(tool_hooks=...)`), as it does with any tool hooks on an agent.
- **No stub without a result.** A tool that raises leaves no stub; Agno
  hands the model its error, as it does for any tool. A tool that is a
  generator function is not run: its body runs only as its results are
  read, so its stub would be written for an action not yet taken.
- **A tool that raises Agno's `RetryAgentRun` or `StopAgentRun` leaves a
  stub.** In Agno a tool raises `RetryAgentRun` to send the model back
  with a message (to try again, or to do more) and `StopAgentRun` to end
  the run; Agno's own examples raise them after the tool has acted, and
  the hook cannot tell whether it has. So the call is recorded as an
  action taken, and Agno is then handed the exception and does what it
  asks. A stub counts against the slip's limits. To refuse the model's
  input with no stub, do it before the tool acts in a way the hook sees:
  a limit in the parameter's type hint (`Annotated[int, Field(le=50)]`),
  which the hook checks first, or an ordinary error (`ValueError`)
  raised by the tool, which leaves no stub. Agno hands the model the
  message in both cases.
- **A call that Agno answers from its cache gets a stub,** although the
  tool is not run: do not let Agno keep the results (`cache_results`) of
  a tool that acts.
- **A team hands a task to a member** (`delegate_task_to_member`, or
  `delegate_task_to_members` for all of them; in task mode,
  `execute_task`, or `execute_tasks_parallel` for several tasks) **only
  where what the member does will be recorded:** the member must carry
  hooks of the same stub writer (`tool_hooks=ProvaredToolHook(writer,
  ...).hooks`, with that member's own tools described), so that its tool
  calls go into the same book and count against the same slip. The
  hand-over itself then leaves no stub; what the member does leaves one.
  A member without such hooks, with hooks of another writer, or on
  another service (Agno's remote agents and teams, which hooks here can
  never record) is not handed the task: the model is told why and how to
  allow it, and Python gives a `RuntimeWarning`. So is a member whose
  hooks let the tools they do not describe run unrecorded
  (`unlisted="run"`), unless the team's own hook was set the same way:
  otherwise a hand-over would let through what the team's hook refuses.
  `execute_tasks_parallel` hands each task to the member the team's own
  list of tasks names, as Agno keeps that list, not as the session
  state holds a copy of it, which the model may be able to change; where
  a task or its member cannot be found, nothing is handed over. In an
  asynchronous run Agno starts a hand-over only once every call of the
  model's reply has been through the hooks, and another call of that
  reply (`execute_task`, where it is described) may give a task to
  another member in between; so `execute_tasks_parallel` is checked
  again as Agno starts it, and refused then in the same way. To hand
  over to such a member all the same, describe the hand-over to the
  hook (for example `'delegate_task_to_member':
  'provared.agent.instruct'`): it is then recorded under that
  description, as the action of handing over, when the task is handed
  over; what the member then does is not recorded.
- **The session state and a team's list of tasks pass unrecorded.**
  Agno's own `update_session_state` changes the run's session state, and
  in task mode `create_task`, `update_task_status`, `list_tasks`,
  `add_task_note` and `mark_all_complete` keep the team's list of tasks
  in it. None of these is an action on the world: they are Agno's way of
  steering the run, as a hand-over is, and they pass without a stub
  unless you describe them. But a stub holds only a call's arguments:
  **a tool that reads the session state (a cart, a list of steps) has a
  stub that does not hold what it read.** Pass what matters to an action
  as the tool's arguments, so that its stub fixes it.
- **Agno's own tools are known by their name and by the part of Agno
  that makes them**, so a tool of your own with the same name is treated
  as any other. A described one is always recorded under its
  description. Agno's other tools, such as searching the agent's
  knowledge or its memory of the person, are treated as any other tool:
  describe them, or they are refused.
- **Ordinary and asynchronous runs** both work (`run` and `arun`). In an
  asynchronous run the second part has Agno take every call through its
  asynchronous path. The stub writer, an ordinary function that may
  wait, runs in a thread of its own for each call; an asynchronous tool
  runs on the event loop, and an ordinary tool in a thread of its own.
  So no call waits for the writer in one of the event loop's shared
  threads, which a tool may need. A tool that cancels itself cancels the
  run, as it would without the hook.
- **Cancelling a run** cancels an asynchronous tool that is waiting: no
  stub is written, and the writer goes on. One that catches the
  cancellation and completes all the same gets its stub, and the writer
  waits for it until then. An ordinary tool that is already running
  cannot be stopped: the call ends only when the tool does, however
  often it is cancelled, so the writer waits until it ends, the next
  action cannot start while it still acts, and its stub is written if it
  completes. This holds where the program's event loop
  then ends at once too (`asyncio.run` cancels every task left): the
  event loop ends only when the tool has.
- **Where the program stops or closes its event loop while a call is
  under way** (for example `loop.run_until_complete(asyncio.wait_for(...))`
  that runs out of time, followed by `loop.close()`), the writer is not
  held for ever. An ordinary tool goes on in its own thread to its end:
  its stub is written if it completes, and the writer is then freed. An
  asynchronous tool needs its event loop to go on: one that had ended
  when the event loop stopped gets its stub; one that had not is taken
  as not completed once the event loop has closed, or has stopped after
  the call was cancelled, so no stub is written, and the writer is
  freed. It may have acted in part. An event loop that has only stopped,
  and not closed, may be run again, and the call then carries on; until
  then the writer waits for it, so do not read the writer from ordinary
  code in that state. Only a program that stops its process outright
  cuts an ordinary tool short; its stub is then not written.
- **Where an ordinary run is made inside a running event loop,** as in a
  notebook, Agno skips the second part and says so in its log, once for
  each tool call; the hook still records every call. On Python 3.11,
  which cannot mark the second part as asynchronous only in an
  asynchronous run, Agno says so in every ordinary run.
- **In an asynchronous program, read the writer with
  `await hook.snapshot()`**, which waits in a thread of its own. Do not
  call the writer on the event loop while an agent may be running, and
  do not read it from the event loop's shared threads
  (`asyncio.to_thread`): there a read waits for the action the writer is
  taking, and enough such reads at once leave no shared thread for a
  tool that needs one, which then waits for ever.
- **One call at a time.** The stub writer takes one call at a time and
  holds it while the tool runs, so tools that Agno would run side by
  side run one after another.
- **A tool must not call the stub writer.** From the tool itself, such a
  call is refused at once. From a thread that the tool starts without
  its context, it waits until the tool ends, so the tool must not wait
  for it.
- **It covers the tool calls that pass through the agent's tool hooks.**
  A tool that the model's own service runs on its side, a tool that Agno
  hands back to you to run (`external_execution`), and tools that
  another tool calls from inside its own run are not recorded one by
  one.
- **A fingerprint can be guessed** where the arguments are few and easy
  to guess, such as one short name. A secret in the arguments is
  fingerprinted by its value, so a short or guessable secret can be
  found from the stub by trying values: give a tool a reference to a
  secret kept elsewhere, not the secret itself, where that matters.
- **What the record shows, and what it does not,** is set out in
  Provared's README and its
  [list of threats](https://github.com/provared/provared/blob/main/docs/threat-model.md).
  In short: it shows what was recorded under a slip the person signed,
  not what was left out, and not whether an action was wise or lawful.

## Tests

In a copy of the repository (the tests use the invented world in
`python/examples/`), from this folder, with Agno and Provared installed:

```
PYTHONPATH=src python -m unittest discover -s tests
```

Agno offers no stand-in model, so the tests run an agent with a small one
written on Agno's own model class, which gives replies scripted in
advance. No AI service is called, Agno's telemetry is switched off, and
a guard refuses any connection outside the program while they run. The
tests in which a call could wait for ever (many calls at once, reads of
the writer while tools run, an event loop stopped or closed under a
call) each run in a process of their own, so that such a call fails its
test rather than stopping the others.

## Licences

As for the rest of the repository: the Apache License 2.0 for the code,
and Creative Commons Attribution 4.0 for this page.
