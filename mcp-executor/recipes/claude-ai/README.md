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
- **The owner's check is not built yet.** The guard's page asks the owner
  to prove who they are before a connection is approved. The check is
  behind an interface, and the one by the owner's passkey is a proposal
  that waits for a decision (the guard's DESIGN.md, section 14.1). So the
  command `provared-mcp-executor http` approves no connection yet: its page
  says so.
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
