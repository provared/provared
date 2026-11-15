# The guard as a claude.ai custom connector

This recipe is the settings for one client: claude.ai, which adds a remote
MCP server as a "custom connector" and signs in to it through OAuth. The
guard (`provared-mcp-executor`) is run by a business on its own server, in
front of one tool server: an upstream HTTP MCP server, or a local program
the guard starts. claude.ai connects to the guard; the guard checks each
tool call against the permission, sends on what it allows, with the
upstream's token or to the program it started with its credential, and
writes a receipt for each in the connection's book.

It describes only what is built, in version 0.5.0 (not yet released). It
has been tried only by the package's own tests, on one computer, with a
stand-in client. It has not been tried with claude.ai itself.

## What claude.ai needs, and what the guard gives

- **The client's document.** claude.ai names itself by the URL of its
  client metadata document, `https://claude.ai/oauth/mcp-oauth-client-metadata`.
  Its redirect address is `https://claude.ai/api/mcp/auth_callback`, and it
  signs in with no client secret (`token_endpoint_auth_method` `none`).
  The guard takes it only because the settings list that URL in
  `oauth.clients`, fetches the document itself, and keeps a copy, so that
  a moment when the document cannot be fetched does not stop the
  connection.
- **The list admits claude.ai, not an account there.** Anyone with a
  claude.ai account can add the guard's address as a connector and get a
  genuine link to the guard's page. Only the owner's approval makes a
  connection. The page cannot tell whose request it shows, so the owner
  approves only a connection they began themselves, just now, and refuses
  a page that came as a link from someone else.
- **Discovery, sign-in and tokens**, as the guard's README says under
  "Signing in through OAuth": the 401 that names the metadata, the page,
  PKCE with S256, codes used once, access tokens for one hour, refresh
  tokens rotated at each use.
- **Time.** claude.ai gives a tool call up to 240 seconds, but a sign-in
  request and a refresh far less: 10 and 30 seconds. The example sets
  `timeout` to 230,000 ms, so that the guard answers a slow call, with its
  receipt, first. The guard's token endpoint and its metadata make no
  request to anyone, and answer at once.

## The limits

- **Port 443 only.** claude.ai reaches a connector on port 443.
- **HTTPS from a reverse proxy.** The guard speaks plain HTTP on
  127.0.0.1. A reverse proxy on the same server must give it HTTPS on port
  443 at the address in `oauth.issuer`, with a certificate that a public
  authority signed, and pass the path and the `Origin` header on unchanged.
- **A public IPv4 address.** claude.ai connects from its own servers, over
  the internet, so the proxy must be reachable at a public IPv4 address.
- **The owner's passkey belongs to the public address.** The guard's page
  asks for the owner's passkey before a connection is approved (the
  guard's DESIGN.md, section 14.1). The passkey is tied to the host in
  `oauth.issuer`. If that address changes, the passkey no longer works
  there; the recovery code still approves a connection, and
  `owner --reset` makes a new owner at the new address.
- **Any passkey that verifies its user.** The guard asks nothing more of
  the passkey than a fingerprint, a face or a PIN at each use. The browser
  offers where to keep it: on this device, on a phone or on a security
  key.
- **Tried with a virtual authenticator, not with a device.** The tests run
  the page's script on a stand-in page with a software passkey, and read
  the headers the pages are sent with. Outside the tests, the pages were
  run in headless Chromium 153 with a virtual authenticator, at
  `http://localhost`: the setup and the first approval in one prompt, a
  later approval, and one by the recovery code, each through to a tool
  call. No passkey on a device (a computer's own, a phone, a security key)
  has been tried, and neither has claude.ai itself. The steps below try
  the real thing by hand.
- **An approval is not in the book.** The guard's log says when a
  connection was approved and for which client; the agent's book holds
  only the receipts of its calls.
- **The upstream needs a fixed token.** The guard sends an upstream HTTP
  server a bearer token read from a file. An upstream that only signs in
  through OAuth itself is not served yet. A local program is given its
  credentials in its environment, each read from a file.
- **A local program serves sessions.** In front of a local program the
  guard starts one program for each session that claude.ai begins, and
  ends it when the session ends, has had nothing from claude.ai for half
  an hour (`sessions.idle`), or makes room for a ninth (`sessions.max`).
  A request under an ended session is answered 404, after which a client
  is to begin a new session. Whether claude.ai does so has not been
  tried.
- **Which revisions of MCP a local program is served on.** In front of a
  local program the guard serves clients and programs that speak revision
  2025-11-25 of the MCP specification (and 2025-06-18 and 2025-03-26,
  which have the same transport). Revision 2026-07-28, which has no
  sessions, is not yet supported in this mode: a request whose
  `MCP-Protocol-Version` header names it is refused with 400, and a
  program that speaks it alone cannot be served. In front of an upstream
  HTTP server the header goes on to the upstream, which answers for it.
- **A tool's question needs the stream.** What a local program sends of
  its own (the progress of a call, a question a tool asks during it) goes
  on the session's GET stream. Where the client has none open it is
  dropped, and a call that waits for an answer to such a question ends at
  the guard's `timeout`.
- **No one-command setup yet.** The keys, the permission and the proxy are
  set up by hand, as for any agent over HTTP.

## The files

- `executor-oauth.example.json`: the settings, with one agent kept for the
  connection (`claude-1`, `"oauth": true`). Put in the upstream's address
  and token file, the proxy's public address and the passkey's thumbprint.
  Make the keys with `provared-mcp-executor keys --config …`, and have the
  permission signed for that agent, as the guard's README says.

To let a second claude.ai connection in, add a second agent marked
`"oauth": true`. Each approved connection is one agent, with its own
permission and book.

## Trying it with the demonstration's server

To try the connector with no tool server of your own, run
`provared-mcp-executor init --http --demo` in a new folder. It writes
`executor-http.json`, `content-rules.json` and `demo-token`. The settings
run the demonstration's made-up server as a local program behind the
guard: two tools, `echo` and `add`, which reach no network. One agent,
`connection-1`, is kept for the connection. Then:

1. In `executor-http.json`, set `oauth.issuer` to the proxy's public
   address and `oauth.clients` to
   `["https://claude.ai/oauth/mcp-oauth-client-metadata"]`.
2. Make the keys with `provared-mcp-executor keys --config executor-http.json`.
   Have the permission signed for the agent `connection-1`, for the
   actions `demo.echo` and `demo.add`; save it as
   `slips/connection-1.json`, and put the passkey's thumbprint in the
   agent's `issuerKeys`.
3. Go on from step 1 of "Trying the owner's passkey by hand", below, with
   `executor-http.json` as the settings.

In claude.ai the connector then shows the two tools. `echo` with a text
that holds the lower-case word "password" is refused by the
demonstration's rule on content, and a denial is written; any other call
to either tool gets a receipt in `books/connection-1.jsonl`. This has been
tried only by the package's own tests, with a stand-in client.

## Trying the owner's passkey by hand

A passkey cannot be made at `http://127.0.0.1`: WebAuthn takes no IP
address as a passkey's site. So try it at the proxy's https address. Below,
`https://guard.example.com` stands for that address, and
`executor-oauth.json` for the settings.

1. Set up the settings, the keys and the permission as above, and start
   the proxy. `provared-mcp-executor check --config executor-oauth.json`
   lists no problem.
2. With the guard stopped, run
   `provared-mcp-executor owner --config executor-oauth.json`. It prints a
   link, `https://guard.example.com/oauth/owner#…`. Copy it.
3. Start the guard: `provared-mcp-executor http --config executor-oauth.json`.
4. Within 15 minutes, open the link in the browser you use claude.ai in.
   The page says what can be done next. Press nothing there, and leave it.
5. In claude.ai, in the same browser, add a custom connector with the
   address `https://guard.example.com/mcp`. claude.ai opens the guard's
   page, headed "Approve claude.ai connecting to your guard". Choose the
   agent and press Approve: one passkey prompt, which makes the owner's
   passkey and approves this connection. The browser offers where to keep
   the passkey (this device, a phone, a security key). The page then shows
   a recovery code: write it down, then press Continue. The browser goes
   back to claude.ai, which shows the connector as connected. The guard's
   log shows `"event":"owner-set"` and `"event":"oauth-approved"` with
   `"by":"setup"`, and the state file (`oauth-state.json`) has an `owner`.
   A tool call then gets a receipt in that agent's book. Note which
   browser and which place for the passkey worked.

   If claude.ai's page was opened before the link, it says that the guard
   has no owner yet. Press "Keep this connection for the setup link" on
   it, open the link in the same browser within 10 minutes and press
   "Review the connection that is waiting": the same page comes back, and
   Approve there is the one prompt. To make the passkey without approving
   anything, press "Make the passkey" on the setup page instead.

   If the page says that the guard's answer did not arrive, press again.
   Where it then says that an owner is already set up, the setup
   finished and only the recovery code was not shown: the passkey
   approves; `owner --reset` and a new setup give a code.

   Two things to watch, the first time:
   - **The answer is refused** with "The answer must come from the
     executor's own page", and the log shows `origin-refused`. The form
     must reach the guard with the `Origin` header of the guard's own
     address. The pages are sent with `Referrer-Policy: same-origin` so
     that a browser gives it; the tests read that header, and headless
     Chromium 153 gave it at the local address, but no other browser and
     no proxy has been tried. Look at the request's `Origin` in the browser's
     network view, and check that the proxy passes it on unchanged.
   - **The page seems stuck after Approve**, though the log shows
     `oauth-approved`. The page's policy lets its form go only to the
     guard and to the origin of claude.ai's redirect address
     (`form-action`), and Chrome applies that to every hop after the
     form. If claude.ai's callback sends the browser on to another host,
     or to an app's own address, the browser stops there, with a
     `form-action` message in its console. The connection was made all the
     same: claude.ai got the code. Note the address the browser was sent
     on to; the guard does not yet answer that case.
6. Open the setup link again. The page says that an owner is already set
   up, and that the link is of no more use.
7. Begin the connection again from claude.ai, and press Approve: one
   passkey prompt, and the browser goes back to claude.ai (the log:
   `"by":"passkey"`). Then once more, in a browser without the passkey:
   type the recovery code in its box, then press Approve. No prompt
   follows. The guard says that the code you typed is spent, and that no
   new one takes its place. Press Continue, once; the browser goes back
   to claude.ai (the log: `"owner-recovery-spent"`, then `"by":"recovery"`).
   The next authorisation page has no box for a code, and says that the
   code is spent. A new code comes from `owner --reset` and a new setup.
8. Look at the headers: `curl -sI https://guard.example.com/oauth/owner`
   shows `content-security-policy: default-src 'none'; script-src 'self';
   connect-src 'self'; form-action 'self'; frame-ancestors 'none';
   base-uri 'none'` and `referrer-policy: same-origin`. The browser's
   console on either page shows no blocked script.
9. To start again: stop the guard and run
   `provared-mcp-executor owner --config executor-oauth.json --reset`. It
   says the owner was removed and how many connections ended. claude.ai
   must then connect again, with a new owner.
