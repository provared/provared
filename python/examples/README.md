# Examples: Provared beside an agent framework

Three small examples. Each builds an agent with one framework, puts the
agent's tools behind Provared's stub writer with `record_function`, and
runs the agent once.

| File | Framework |
|---|---|
| `langchain_example.py` | LangChain (`create_agent`, with LangGraph underneath) |
| `openai_agents_example.py` | OpenAI Agents SDK |
| `pydantic_ai_example.py` | Pydantic AI |

## What each example shows

- **The tools are ordinary functions**, with type hints and a docstring:
  `order_supplies` and `send_message`.
- **`record_function` keeps what the framework reads.** The recorded
  function has the same name, parameters, types and docstring as the
  plain one. So the framework describes it to its model exactly as it
  would describe the plain function. Each example prints the tools as
  the model was told of them.
- **The slip.** An invented person signs a slip. It lets the agent order
  supplies from an invented supplier, up to 100 GBP in all, and send
  messages.
- **The run.** The model asks to order printer paper for 30 GBP. That is
  inside the slip: the tool runs and a stub is written. Then the model
  asks to order a standing desk for 250 GBP. That would go over the
  limit: the tool is not run, nothing is written, and the agent is told
  why, in the words of `NotTaken`:

  ```
  The tool "order_supplies" was not run. With this action the total would be 280 GBP.
  The slip's limit is 100 GBP: over by 180.
  ```

  Then the model answers.
- **The check.** The book is checked with `check_book`, naming the
  passkey the checker trusts. It is intact, the agent stayed within its
  slip, and it holds one stub. A call that was not run leaves no stub:
  the book shows what was done, not what was asked for.

Each framework needs one setting so that the agent is told why a call
was not run. Without it, the error either stops the run or is hidden
from the model:

- LangChain: `ToolErrorMiddleware`, which hands the message back as a
  failed tool call.
- OpenAI Agents SDK: `failure_error_function` on each tool. The SDK's own
  default tells the model only that an error happened.
- Pydantic AI: a `Hooks` capability with `tool_execute_error`, which
  hands the message back as `ToolFailed`.

For LangChain and Pydantic AI there is also a ready class that puts
every tool call of an agent behind the stub writer, with no change to
the tools: `ProvaredMiddleware` in the package `provared-langchain`, and
`ProvaredCapability` in the package `pydantic-ai-provared`. Both are in
[`../integrations/`](../integrations).

A recorded tool takes plain data only: text, numbers, lists, dicts,
True, False and None. So a tool that takes the framework's own context
object (Pydantic AI's `RunContext`, LangChain's `ToolRuntime`), or a
model class as a parameter, cannot be recorded with `record_function`:
it refuses such a function when it is handed it, and names the
parameter.

Each framework runs an ordinary function in a thread of its own. That
matters because the stub writer may wait: it signs each stub, takes one
call at a time, and gives the other side up to 30 seconds to
countersign where it is asked to.

## For demonstration only

- **The passkey is a software stand-in.** It is a key made in memory. It
  is not a passkey and confirms no person. A real slip is signed by the
  person, in a browser, with a real passkey.
- **The models are the frameworks' own stand-ins, scripted in advance.**
  No AI service is called. LangChain's is `GenericFakeChatModel`, the
  OpenAI Agents SDK's is `ScriptedModel`, and Pydantic AI's is
  `FunctionModel`.
- **Everything is invented:** the person, the agent, the supplier, the
  orders and the money.
- **Nothing is sent anywhere.** No API key is set. Each framework's
  tracing or instrumentation is switched off in the code. Each example
  runs inside `offline()` (in `_world.py`). While it is open, it refuses
  any look-up of a name other than this computer's, any connection or
  message to anything but a socket of the same program (so not to a
  proxy on this computer either), and starting another program. It
  works through Python's audit events, and on Windows also checks the
  event loop's connections, which raise none. The tests check that
  nothing was refused while each example ran, so an attempt that a
  framework caught and set aside would still show. It guards a
  demonstration; it is not a sandbox for code you do not trust.

## How to run them

You need Python 3.11 or later. From this folder:

```
python -m venv ../.venv-examples
../.venv-examples/Scripts/pip install -r requirements.txt     # on Linux or macOS: ../.venv-examples/bin/pip
../.venv-examples/Scripts/pip install -e ..
../.venv-examples/Scripts/python langchain_example.py
../.venv-examples/Scripts/python openai_agents_example.py
../.venv-examples/Scripts/python pydantic_ai_example.py
```

`requirements.txt` pins each framework to an exact version. Installing
them downloads packages from the Python Package Index; running the
examples sends nothing.

The tests run each example and check what it shows:

```
../.venv-examples/Scripts/python -m unittest test_examples -v
```

## Licences

As for the rest of the repository: the Apache License 2.0 for the code,
and Creative Commons Attribution 4.0 for this page.
