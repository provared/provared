# pydantic-ai-provared

A Pydantic AI capability that checks each tool call of an agent against
the permission a person signed, runs the tool only if the permission
allows it, and records the call with
[Provared](https://github.com/provared/provared).

*Evidence, not a verdict.*

**Version 0.1.0, a draft**, as Provared itself is. Published as it is, by
one author in their own time; fixes as time allows.

## What it does

Provared is a way to prove what an AI agent was allowed to do, and what
it then did. A person signs a **slip** with a passkey: which agent, which
actions, which limits, until when. Beside the agent, Provared's stub
writer checks each action against the slip before it is taken and, if it
is allowed, writes a signed **stub** for it into a book that anyone can
check later.

`ProvaredCapability` puts every tool call of a Pydantic AI agent behind
that stub writer:

- **Allowed:** the tool runs, and a stub is written. The stub names the
  action, the amount and the other party where they apply, and the
  SHA-256 fingerprint of the call's arguments, so the record fixes
  exactly what was asked for without holding it.
- **Not allowed** (over a limit, an action the slip does not name, after
  the slip ends or was cancelled): the tool is not run, nothing is
  written, and the model is handed a failed tool answer (`ToolFailed`)
  that says why, for example: `The tool "order_supplies" was not run.
  With this action the total would be 280 GBP. The slip's limit is 100
  GBP: over by 180.`
- **A tool that is not described** to the capability is not run either,
  unless you pass `unlisted="run"`. Pydantic AI's own tools for the
  agent's final output always run: they are not tool calls here.

## Install

```
pip install pydantic-ai-provared
```

You need Python 3.11 or later. It installs `provared` and
`pydantic-ai-slim`.

## Use

```python
from pydantic_ai import Agent
from provared import open_recorder
from pydantic_ai_provared import ProvaredCapability

# The stub writer, on the book that holds the person's signed slip.
writer = open_recorder(book_text, slip_fingerprint, agent_private_keys, issuer_keys=[passkey_thumbprint])

agent = Agent(model, tools=[order_supplies, send_message], capabilities=[
    ProvaredCapability(writer, {
        'order_supplies': {'action': 'supplies.order', 'with': 'supplier',
                           'amount': lambda args: {'unit': 'GBP', 'value': args['total_gbp']}},
        'send_message': 'provared.message.send',
    }),
])

agent.run_sync('Order paper.')
book_text, held = writer.snapshot()   # keep both together
```

For each tool, give the action name the slip uses for it, or a dict as
for `provared.record_tools`, without `run`: `action`, and where they apply
`with`, `amount`, `details`, `countersign` and `approve`. Each is checked
when the capability is made, so a mistake shows when the agent is built.
How to make a slip, a book and the agent's keys is in Provared's
[README](https://github.com/provared/provared/blob/main/README.md) and
[Python README](https://github.com/provared/provared/blob/main/python/README.md).

## What to know

- **The arguments recorded are those the tool is handed**, after Pydantic
  AI has checked them against the tool's schema. They must be plain data
  (text, numbers, lists, dicts, True, False, None): a call with a model
  class or a date among its arguments is not run, and the model is told
  why. Arguments that do not fit the schema never reach the stub writer.
- **No stub without a result.** A tool that raises leaves no stub, and
  its error is passed on. A tool that asks the model to try again
  (`ModelRetry`) or reports a failure (`ToolFailed`), and a call that is
  deferred, leave no stub. If another capability turns a tool's error
  into a result, the stub stands, because the call then gave a result.
- **The stub writer is an ordinary function that may wait,** so it runs
  in a thread of its own, and the tool on the event loop. It takes one
  call at a time, so tool calls that Pydantic AI runs side by side are
  recorded one after another.
- **A tool must not call the stub writer.** Such a call is refused at
  once.
- **What the record shows, and what it does not,** is set out in
  Provared's README and its
  [list of threats](https://github.com/provared/provared/blob/main/docs/threat-model.md).
  In short: it shows what was recorded under a slip the person signed,
  not what was left out, and not whether an action was wise or lawful.

## Tests

From this folder, with Pydantic AI and Provared installed:

```
PYTHONPATH=src python -m unittest discover -s tests
```

The tests run an agent with Pydantic AI's own stand-in model, scripted
in advance. No AI service is called, and a guard refuses any connection
outside the program while they run.

## Licences

As for the rest of the repository: the Apache License 2.0 for the code,
and Creative Commons Attribution 4.0 for this page.
