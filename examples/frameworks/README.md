# Example: Provared beside a JavaScript agent framework

A small example. It builds an agent with the Vercel AI SDK (the npm
package `ai`, with `generateText` and `tool`), puts the agent's tools
behind Provared's stub writer with `recordTools`, and runs the agent
once: `vercel-ai-sdk.mjs`.

Three small files go with it: `_world.mjs` (the invented person, slip and
tools), `_model.mjs` (the scripted stand-in model) and `_offline.mjs`
(the guard that keeps everything on this computer).

## What the example shows

- **The tools are put behind the stub writer once.** `_world.mjs` hands
  the agent's two tools, `orderSupplies` and `sendMessage`, to
  `recordTools`, with the action name the slip uses for each, the
  supplier and the amount. The SDK's own `tool` then calls the recorded
  tool from its `execute` function. Nothing else about the SDK changes.
- **The slip.** An invented person signs a slip. It lets the agent order
  supplies from an invented supplier, up to 100 GBP in all, and send
  messages. The first line printed says that it was signed by a
  development stand-in for a passkey, not by a person.
- **The run.** The model asks to order printer paper for 30 GBP. That is
  inside the slip: the tool runs and a stub is written. Then the model
  asks to order a standing desk for 250 GBP. That would go over the
  limit: the tool is not run, nothing is written, and the agent is told
  why, in the words of `NotTaken`:

  ```
  The tool "orderSupplies" was not run. With this action the total would be 280 GBP.
  The slip's limit is 100 GBP: over by 180.
  ```

  Then the model answers.
- **The check.** The book is checked with `checkBook`, naming the passkey
  the checker trusts. It is intact, the agent stayed within its slip, and
  it holds one stub. A call that was not run leaves no stub: the book
  shows what was done, not what was asked for.

The SDK needs no setting for the agent to be told why a call was not
run: it catches an error thrown by a tool's `execute` function and hands
its words back to the model as a failed tool call, with the error's
name, `NotTaken:`, before them.

The stub of each call names the fingerprint of the call's arguments
(`provared.arguments`), not the arguments themselves. The arguments are
those the SDK hands to `execute`, after it has read them against the
tool's input schema.

## What the example does not show

- **An agent that calls the network itself.** These tools only write
  into a list. A real tool would send the order; Provared would still
  run it only if the slip allows it.
- **A call that goes round the stub writer.** Only tools put behind
  `recordTools` are checked and receipted. A tool given to the SDK
  directly, or code that the agent runs some other way, leaves no trace.
- **Tools given without `execute`.** The SDK then hands the call back to
  your application, which runs it. Such a call is checked and receipted
  only if your application runs it through the recorded tool.
- **Tools that run at the model provider.** Some providers run tools of
  their own (a web search, for example). Those calls never reach your
  code, so nothing checks or receipts them.
- **A tool that fails after it has already acted.** If a tool throws an
  error, no stub is written, by the library's design, even if part of
  the action already happened (an order sent, then a failure reading the
  answer). Your code must deal with what did happen.
- **A call the SDK gives up on.** If a time limit or an abort makes the
  SDK stop waiting for a tool, the tool may still finish, and its stub is
  then written although the model was told the call failed. The SDK's
  abort signal is not passed to the recorded tool's `run` function, so
  the tool cannot see that the SDK gave up.
- **Countersignatures, approvals, seals and denials.** The stub writer
  offers all of them; see `docs/guide.md` at the top of the repository.

## For demonstration only

- **The passkey is a software stand-in.** The slip is signed with the
  library's development stand-in (`provared/dev`): a key made in memory.
  It is not a passkey and confirms no person, and the issuer's name in
  the slip ends with "(development)". A real slip is signed by the
  person, in a browser, with a real passkey.
- **The model is scripted in advance.** No AI service is called. The
  example uses the SDK's own mock model for tests, `MockLanguageModelV4`
  from `ai/test`. Its answers are written in `_model.mjs`.
- **Everything is invented:** the person, the agent, the supplier, the
  orders and the money.
- **Nothing is sent anywhere.** No API key is set. In the code of version
  7.0.153, the SDK sends no usage reports of its own. Besides the model it is
  given, it may download files named by web address in the messages, and
  its chat helpers call an address the application gives; the guard
  refuses all of these here. The example passes
  `telemetry: { isEnabled: false }`, which stops the SDK handing events
  to any telemetry add-on (none is installed here).
- **The guard.** `npm start`, and the run's tests in `npm test`, load
  `_offline-whole-run.mjs` first (the guard's own tests open and close
  it themselves), which opens the guard in `_offline.mjs` before any other module
  is loaded and keeps it open until the program ends; run as
  `node vercel-ai-sdk.mjs`, the example opens it itself, after its
  imports. While it is open, it replaces with functions that refuse:
  `net.Socket.prototype.connect` (which every TCP connection made through
  Node.js's own modules goes through, among them `http`, `https`, `http2`
  and `fetch`), `net.connect`, `net.createConnection` and `tls.connect`;
  the `send` and `connect` of `dgram` sockets; every `dns` and
  `dns.promises` function whose name begins "lookup", "resolve" or
  "reverse", and those of both `Resolver` classes; the functions of
  `child_process` that start a program, `process.execve` where it exists, and
  `ChildProcess.prototype.spawn`; `worker_threads.Worker`;
  `globalThis.fetch` and `globalThis.WebSocket`; and `process.binding`
  for the bindings beneath those modules. The tests check that nothing
  was refused, during the run or in the second after it, so an attempt
  that the SDK caught and set aside would still show. It guards a
  demonstration; it is not a sandbox for code you do not trust: a native
  add-on, or a function kept from before the guard was opened, could
  still reach the network.

## How to run it

You need Node.js 24.7 or later. From this folder:

```
npm ci --ignore-scripts
npm start
npm test
```

`package.json` pins each package to an exact version, and
`package-lock.json` fixes every package beneath them. Installing them
downloads packages from the npm registry; running the example sends
nothing. The example takes the library from this repository
(`"provared": "file:../.."`), so it tests the library as it is in this
copy. In your own project, `npm install provared` instead.

| Package | Version | Licence |
|---|---|---|
| `ai` (the Vercel AI SDK) | 7.0.153 | Apache License 2.0 |
| `zod` | 4.6.7 | MIT |

This example, and the folder it lives in, are not part of the npm
package `provared`.

## Licences

As for the rest of the repository: the Apache License 2.0 for the code,
and Creative Commons Attribution 4.0 for this page.
