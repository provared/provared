# The guard as a claude.ai custom connector

This recipe is the settings for one client: claude.ai, which adds a remote
MCP server as a "custom connector" and signs in to it through OAuth. The
guard (`provared-mcp-executor`) is run by a business on its own server, in
front of one upstream MCP server. claude.ai connects to the guard; the
guard checks each tool call against the permission, sends on what it
allows with the upstream's token, and writes a receipt for each in the
connection's book.

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
- **Discovery, sign-in and tokens**, as the guard's README says under
  "Signing in through OAuth": the 401 that names the metadata, the page,
  PKCE with S256, codes used once, access tokens for one hour, refresh
  tokens rotated at each use.
- **Time.** claude.ai gives a tool call, a sign-in request and a refresh up
  to 240 seconds. The example sets `timeout` to 230,000 ms, so that the
  guard answers a slow call, with its receipt, first.

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
  `oauth.issuer`. If that address changes, the passkey no longer opens the
  owner's key, and only the recovery code does.
- **A browser with PRF.** The passkey must give the PRF extension, in the
  browser and in the place that keeps the passkey. Where it does not, the
  setup stops and sends nothing; at the page, the recovery code still
  works.
- **Not tried in a real browser yet.** The tests run the page's own steps
  with a stand-in passkey. The steps below try the real thing by hand.
- **The upstream needs a fixed token.** The guard sends the upstream a
  bearer token read from a file. An upstream that only signs in through
  OAuth itself is not served yet.
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
4. Within 15 minutes, open the link in the browser that is to hold the
   passkey. Press "Make the passkey" and accept the browser's prompts. The
   page shows a recovery code: write it down. The guard's log shows
   `"event":"owner-set"`, and the state file (`oauth-state.json`) has an
   `owner`.
5. Open the same link again and press the button. The page says that an
   owner is already set up.
6. In claude.ai, add a custom connector with the address
   `https://guard.example.com/mcp`. claude.ai opens the guard's page.
   Choose the agent, press Approve, and use the passkey. The browser goes
   back to claude.ai, which shows the connector as connected. The guard's
   log shows `"event":"oauth-approved"`. A tool call then gets a receipt in
   that agent's book.
7. In a browser without the passkey, begin the connection again. Type the
   recovery code in its box, then press Approve. It is approved in the
   same way.
8. Look at the headers: `curl -sI https://guard.example.com/oauth/owner`
   shows `content-security-policy: default-src 'none'; script-src 'self';
   connect-src 'self'; form-action 'self'; frame-ancestors 'none';
   base-uri 'none'`. The browser's console on either page shows no
   blocked script.
9. To start again: stop the guard and run
   `provared-mcp-executor owner --config executor-oauth.json --reset`. It
   says the owner was removed and how many connections ended. claude.ai
   must then connect again, with a new owner.
