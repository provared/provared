# <img src="https://prova.red/favicon.svg" alt="" width="36"> provared-langchain

A LangChain middleware that checks each tool call of an agent against
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

`ProvaredMiddleware` puts every tool call of a LangChain agent
(`create_agent`) behind that stub writer:

- **Allowed:** the tool runs, and a stub is written. The stub names the
  action, the amount and the other party where they apply, and the
  SHA-256 fingerprint of the call's arguments, so the record fixes
  exactly what was asked for without holding it.
- **Not allowed** (over a limit, an action the slip does not name, after
  the slip ends or was cancelled): the tool is not run, nothing is
  written, and the model is handed a failed tool answer that says why,
  for example: `The tool "order_supplies" was not run. With this action
  the total would be 280 GBP. The slip's limit is 100 GBP: over by 180.`
- **A tool that is not described** to the middleware is not run either,
  unless you pass `unlisted="run"`: the model is told, and Python gives a
  `RuntimeWarning`, so that a misspelt name shows.

## Install

```
pip install provared-langchain
```

You need Python 3.11 or later. It installs `provared`, `langchain`,
`langchain-core` and `pydantic`.

## Use

```python
from langchain.agents import create_agent
from provared import open_recorder
from provared_langchain import ProvaredMiddleware

# The stub writer, on the book that holds the person's signed slip.
writer = open_recorder(book_text, slip_fingerprint, agent_private_keys, issuer_keys=[passkey_thumbprint])

# Last in the list: any middleware that wraps tool calls goes before it.
agent = create_agent(model, tools=[order_supplies, send_message], middleware=[
    ProvaredMiddleware(writer, {
        'order_supplies': {'action': 'supplies.order', 'with': 'supplier',
                           'amount': lambda args: {'unit': 'GBP', 'value': args['total_gbp']}},
        'send_message': 'provared.message.send',
    }),
])

agent.invoke({'messages': [{'role': 'user', 'content': 'Order paper.'}]})
book_text, held = writer.snapshot()   # keep both together
```

For each tool, give the action name the slip uses for it, or a dict as
for `provared.record_tools`, without `run`: `action`, and where they apply
`with`, `amount`, `details`, `countersign` and `approve`. Each is checked
when the middleware is made, so a mistake in a description, such as a
misspelt member, shows when the agent is built.
How to make a slip, a book and the agent's keys is in Provared's
[README](https://github.com/provared/provared/blob/main/README.md) and
[Python README](https://github.com/provared/provared/blob/main/python/README.md).

## What to know

- **It must come last** among the middleware that wrap tool calls (human
  review, retries, error handling, caching): put those before it. Then a
  reviewer's change, or each retry, is checked and recorded as the call
  the tool receives, and nothing can answer in the tool's place after
  the check. If it is not last, the first tool call raises
  `provared.Refusal`.
- **The arguments are checked against the tool's schema first**, as
  LangChain checks them, and written in their JSON form. That form is
  what is fingerprinted, what the functions in a tool's description
  (`amount`, `with` and so on) are handed, and what the tool is run
  with; LangChain then reads it as it reads a model's arguments. So
  `"30"` given for a whole number is recorded as `30`. A call that does
  not fit is not run, and the model is told what is wrong.
- **No stub without a result.** A tool that raises leaves no stub, and
  its error is passed on, as LangChain passes it on. A tool that answers
  with an error leaves no stub either.
- **Ordinary and asynchronous agents** both work (`invoke` and
  `ainvoke`). In an asynchronous agent the stub writer, an ordinary
  function that may wait, runs in a thread of its own for each call, and
  the tool runs on the event loop. Cancelling a run cancels a tool that
  is waiting: no stub is written, and the writer goes on. An ordinary
  tool that LangChain is already running in a thread cannot be stopped:
  it finishes, and leaves no stub, because its call was cancelled.
- **In an asynchronous program, do not call the stub writer on the event
  loop while an agent may be running**, not even `writer.snapshot()`: it
  waits for the action it is taking, and that action needs the event
  loop. Call it from a thread: `await asyncio.to_thread(writer.snapshot)`.
- **One call at a time.** The stub writer takes one call at a time and
  holds it while the tool runs, so tools that LangChain would run side by
  side run one after another.
- **A tool must not call the stub writer.** From the tool itself, such a
  call is refused at once. From a thread that the tool starts without
  its context, it waits until the tool ends, so the tool must not wait
  for it.
- **It covers the tool calls that LangChain runs.** A tool that the
  model's own service runs on its side, such as a built-in web search,
  never reaches LangChain's tools and is not recorded.
- **A fingerprint can be guessed** where the arguments are few and easy
  to guess, such as one short name.
- **What the record shows, and what it does not,** is set out in
  Provared's README and its
  [list of threats](https://github.com/provared/provared/blob/main/docs/threat-model.md).
  In short: it shows what was recorded under a slip the person signed,
  not what was left out, and not whether an action was wise or lawful.

## Tests

In a copy of the repository (the tests use the invented world in
`python/examples/`), from this folder, with LangChain and Provared
installed:

```
PYTHONPATH=src python -m unittest discover -s tests
```

The tests run an agent with LangChain's own stand-in model, scripted in
advance. No AI service is called, and a guard refuses any connection
outside the program while they run.

## Licences

As for the rest of the repository: the Apache License 2.0 for the code,
and Creative Commons Attribution 4.0 for this page.
