# The guard as a claude.ai custom connector

This recipe is the settings for one client: claude.ai, which adds a remote
MCP server as a "custom connector" and signs in to it through OAuth. The
guard (`provared-mcp-executor`) is run by a business on its own server, in
front of one tool server: an upstream HTTP MCP server, or a local program
the guard starts. claude.ai connects to the guard; the guard checks each
tool call against the permission, sends on what it allows, with the
upstream's token or to the program it started with its credential, and
writes a receipt for each in the connection's book.

The folder `compose/` runs the guard with Docker Compose, beside Caddy,
which gives it HTTPS (secure HTTP) with a certificate it gets itself. One
command starts both.

It describes only what is built, in version 0.5.1 (published on 22 November 2026). It
has been tried by the package's own tests, on one computer, with a
stand-in client, and by the Docker check described under "What has been
tried". The recipe has not been tried on a real server, with a publicly
signed certificate, or with claude.ai. The guard itself has been, without
Docker or this recipe: on 15 November 2026 an earlier build of this
version ran on a server on the internet, behind Caddy with a Let's
Encrypt certificate. claude.ai connected to it after one passkey prompt
(Windows Hello, in Chrome on Windows); the guard took two tool calls,
saving a countersigned receipt for each, and refused a third under its
content rule before the tool saw it.

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
  request and a refresh far less: 10 and 30 seconds. The guard's
  `timeout` is 230,000 ms where the settings name `oauth`, so that the
  guard answers a slow call, with its receipt, first. The guard's token
  endpoint and its metadata make no request to anyone, and answer at once.

## Setting it up with Docker Compose

What runs, from `compose/compose.yaml`:

- **The guard**, in an image built on the server from npm. The guard and
  its library are exact: the versions `compose/package-lock.json` gives,
  each checked against its SHA-512 hash there (`npm ci`). It runs on the
  official Node.js image, following the release line of Node.js 24
  (`node:24-bookworm-slim`). No image is published anywhere.
- **Caddy**, the official image, following Caddy's 2.11 release line
  (`caddy:2.11-alpine`). It answers
  on ports 80 and 443, gets the certificate for the domain from a public
  certificate authority, renews it, and sends each request on to the
  guard. It writes no access log, and is given no email address.
- **`folders`**, which runs once at each start, before the other two: it
  gives each data folder to the user that writes it, with mode 700, and
  ends.

The guard listens on `127.0.0.1:8796`, its own rule, inside the network it
shares with Caddy. So only Caddy reaches it: its port is published
nowhere, and only Caddy's 80 and 443 are. Caddy passes every path on
except the guard's addresses for its administrator, `/provared` and
everything under it (`status`, `seal`, `acknowledge`, `hello`): for those
Caddy answers 404 itself, so they are reached only on the server, with
`docker compose run --rm guard ...`.

What the server needs: Linux, Docker with its Compose plugin, a public IPv4
address, and ports 80 and 443 open to the internet (443 for claude.ai and
the owner; 80 for Caddy's certificate, and to send a browser on to
https). Nothing else may be listening on 80 or 443.

The recipe was tried with Docker 29.7.2 and Compose 5.5.0 alone. Its
files need BuildKit, the builder of every current Docker
(`Dockerfile.dockerignore`, `COPY --chmod`); no older Docker or Compose
is known to work. The guard and Caddy run as the users 10001 and 10002,
by number, and the README's commands give files to those numbers
(`sudo install -o 10001`). Rootless Docker and user-namespace remapping
map the numbers in a container to others on the server, so those
commands and the folders' owners do not hold there; neither was tried.

### Getting the recipe

Take the recipe from the repository at a signed release tag, and check the
tag's signature before using it. The repository's release tags are named
`v` and the version of the Provared library, such as `v0.8.0`; the guard
has no tags of its own. Use the newest release tag whose
`mcp-executor/recipes/claude-ai/compose/package.json` names the guard's
version you want: `v0.9.1` names 0.5.0, and 0.5.1 comes with the next release tag. `v0.9.0` also names 0.5.0, but its lockfile was made before 0.5.0 was on npm, so `npm ci` stops on it. On the server,
with git, for the tag `<tag>`:

```
git clone --depth 1 --branch <tag> https://github.com/provared/provared.git provared
cd provared
git -c gpg.ssh.allowedSignersFile=.github/release-signers tag -v <tag>
```

The last command must end with
`Good "git" signature for sealwright with ED25519 key SHA256:64cQtHklVRtDUPmbUWpRls28kFcpUnDhFJtpqMHiLbU`.
Anything else (no signature, another key, `BAD`) means: do not use it. Its
output's line `tag <tag>` must name the tag you asked for: git checks the
signature, not the name, so an older signed release handed out under a
newer name passes too. The
file `.github/release-signers` comes from the same repository, so the check
shows that the tag was signed by the key the repository names; compare
that fingerprint with one you have from elsewhere. No second place
publishes it yet: in the repository it is in `.github/release-signers`,
`tools/release/verify-tag.mjs` and this README alone, so the comparison
needs a copy you were given by another road. The recipe is then the
folder `mcp-executor/recipes/claude-ai/compose`.

### The steps

1. **Point a domain at the server**: a DNS `A` record for a name such as
   `guard.example.com`, with the server's public IPv4 address.
2. **Set the domain in one file.** Copy the folder `compose/`, from the
   checked tag, to where it will live on the server. In it, copy
   `example.env` to `.env`, and set
   `PROVARED_DOMAIN=guard.example.com` there. Caddy reads the `Caddyfile`
   as a user of its own: where the copy was made under a strict umask
   (027 or 077), run `chmod 644 Caddyfile`. The guard's image makes its
   own files readable whatever their mode.
3. **Run one command**, in that folder:

   ```
   docker compose up -d --build
   ```

4. **Read what to do next**, in the guard's log:

   ```
   docker compose logs -f guard
   ```

   On the first start the guard writes the settings for the
   demonstration's tools (`init --http --demo`), sets `oauth.issuer` to
   `https://<domain>` and `oauth.clients` to claude.ai's document, makes
   its keys, and then says what is wanted and waits:
   - read what the permission must hold:
     `sudo cat guard-data/permission-entries.json` (public keys only);
   - the person who answers for the guard signs a permission with their
     passkey, at https://sign.prova.red, for the agent `connection-1` and
     the actions `demo.echo` and `demo.add`, holding those entries;
   - put it on the server as `guard-data/slips/connection-1.json`, owned
     by the guard's user:
     `sudo install -o 10001 -g 10001 -m 600 connection-1.json guard-data/slips/connection-1.json`;
   - in `guard-data/executor-http.json`, under
     `agents."connection-1".issuerKeys`, put the thumbprint of the passkey
     that signed it, in place of the value written `<like this>`. The
     signing page shows it once the permission is signed, as "The
     thumbprint of your passkey".

   The guard looks again every 10 seconds. Once both are in place it runs
   `check`; where `check` finds a problem, the log lists it once, and the
   guard runs `check` again every 10 seconds, whichever file was mended
   (`docker compose restart guard` runs it at once).
5. **Read the owner's link.** Once `check` finds no problem, and while the
   guard is not yet running, the start makes the owner's link and writes it
   to `guard-data/owner-link.txt`, readable by the guard's user alone. It
   is not written to the log. Read it with
   `sudo cat guard-data/owner-link.txt`. It works once, within 15 minutes.
   Then the guard starts. A later start keeps a link that still has more
   than two minutes to run; `docker compose restart guard` after that
   makes a new one, and the one before stops working. Once there is an
   owner, the start takes the file away.
6. **Make the owner and the connector**: go on from step 4 of "Trying the
   owner's passkey by hand", below. The connector's address is
   `https://<domain>/mcp`.

Every value is the guard's own: the guard's README, "Signing in through
OAuth" and "Set it up", says what each is.

### Commands, and the owner's reset

The guard's other commands run in a container of their own, with the
guard's settings, as `docker compose run --rm guard <command>`; for
example `docker compose run --rm guard check`.

`owner` changes the state file that the running guard holds a lock on, so
it is run with the guard stopped. To replace the owner (every connection
then ends, with its tokens):

```
docker compose stop guard
docker compose run --rm guard owner --reset
docker compose start guard
```

`owner --reset` writes the new link to `guard-data/owner-link.txt`, prints
where it is rather than the link, and the start keeps it.

Run every command that writes the guard's files with the guard stopped,
as above: `owner`, and any command with `--offline` (`seal --offline`,
`acknowledge --offline`). Commands that only read (`check`, `status`,
`keys --out` to a new file) may run beside it. From the start's first
step, while it waits for the permission too, and for as long as the guard
runs, the start answers at `guard-data/guard-running.sock`, and a command that
writes is refused (code 2) where something answers there. The guard's own
lock refuses it too, but only where the command's container shares the
guard's network, which is not so in the seconds after Caddy's container
is restarted on its own, until the guard has stopped and started again;
the socket file is seen from either network. `docker compose run --rm guard`
with no command is a second start, not a help text: it is refused the same
way (code 2), and leaves the running guard's socket file as it was.

### What to back up, and what is secret

Everything kept is in three plain folders beside `compose.yaml`, never in
a Docker volume. They are what to back up, with `.env`:

- `guard-data`: the guard's keys, the books, the copies, the state file,
  the settings and the permissions. Owned by user 10001, mode 700.
- `caddy-data`: Caddy's certificates and their private keys. Owned by user
  10002, mode 700.
- `caddy-config`: Caddy's own state. Owned by user 10002, mode 700.

The owner's link and the recovery code are secrets: whoever has the link
first becomes the owner, and the code approves a connection. Keep the code
off the server. The key files in `guard-data/keys/` are secret too.

### One copy only

The guard is single-copy: each book has one writer. Run one guard on these
folders, with no replicas and no second copy on another server sharing
them. `compose.yaml` fixes the project's name (`provared-guard`), so two
copies of the folder on one server are one project: `docker compose up -d`
in the second replaces the first's containers with ones on the second's
folders.

### Updates

Updates are not automatic. They come only when this command runs, in the
folder of `compose.yaml`:

```
docker compose pull caddy && docker compose build --pull && docker compose up -d
```

It fetches the newest Caddy 2.11 and Node.js 24 images, builds the
guard's image again on Node.js, and starts again what changed. Node.js and
Caddy follow their release lines, so that the command brings their
security fixes. **So an update can bring a Node.js or Caddy patch that
this recipe has not been tried with.** It was tried with Node.js 24.22.3
and Caddy 2.11.9. To go back to one version, name it in the files and run
the command again: in `Dockerfile`, `FROM node:24.22.3-bookworm-slim`; in
`compose.yaml`, `image: caddy:2.11.9-alpine`. Each file gives the digest
of the version tried, to pin that too.

The tag `caddy:2.11-alpine` brings Caddy's fixes while 2.11 is its newest
line. Once Caddy has a newer minor line, its fixes may go there alone, and
the tag stops moving while the command still succeeds: the recipe must
then move to the newer line, with a newer recipe, or with the name changed
in `compose.yaml` and tried.

The command's last step, `docker compose up -d`, starts every container
of the recipe, a guard stopped on purpose too. While the guard is to stay
stopped, do not run the command, and switch the weekly timer below off.
Each update that brings a newer Node.js or Caddy leaves the image before
it on the disk, with no name; nothing in the recipe takes those away.
`docker image prune` does, for every image on the server with no name and
no container: run it now and then where nothing else on the server needs
such images.

The guard and its library do not move: `package-lock.json` holds them, at
exact versions, with their hashes. To move to a newer guard, take the
newer recipe from its signed tag ("Getting the recipe"), put its
`compose.yaml`, `Dockerfile`, `Dockerfile.dockerignore`, `package.json`,
`package-lock.json`, `start.mjs` and `Caddyfile` in place of these (keep
`.env` and the three folders), then run the command.

A weekly timer that runs the same command is in `compose/weekly/`, off
until the business switches it on. To switch it on:

1. In `provared-guard-update.service`, set `WorkingDirectory` to the
   folder of `compose.yaml`.
2. `sudo cp provared-guard-update.service provared-guard-update.timer /etc/systemd/system/`
3. `sudo systemctl daemon-reload && sudo systemctl enable --now provared-guard-update.timer`

It runs on Monday between 04:00 and 05:00. To switch it off:
`sudo systemctl disable --now provared-guard-update.timer`. Like the
command, the timer can bring a Node.js or Caddy patch not yet tried with
this recipe, and never a newer guard.

### After a restart of the server

Docker starts both containers again itself, in an order of its own. The
guard joins Caddy's network, so it can start only once Caddy runs: started
first, it stops with "cannot join network namespace of a non running
container", and Docker does not try it again. The check below found this
with `docker start` (the guard first, then Caddy): the guard stayed
stopped. A unit in `compose/boot/` starts whichever is stopped, Caddy
first, once Docker has started; it builds nothing and fetches nothing. To
switch it on:

1. In `provared-guard-boot.service`, set `WorkingDirectory` to the
   folder of `compose.yaml`.
2. `sudo cp provared-guard-boot.service /etc/systemd/system/`
3. `sudo systemctl daemon-reload && sudo systemctl enable provared-guard-boot.service`

Without it, run `docker compose up -d` in the folder of `compose.yaml`
after each restart of the server. Which order Docker itself uses when the
server starts was not found out here: Docker was not restarted.

The unit runs once, at each start of the server, and not again until the
next. Where Docker alone is restarted (`systemctl restart docker`, or an
update of Docker's packages), Docker starts the two containers again in an
order of its own and the unit does not run: the guard can stay stopped.
After such a restart, run `docker compose up -d` in the folder of
`compose.yaml`. The unit also starts a guard that was stopped on purpose
(`docker compose stop guard`), as `docker compose up -d` starts every
container: a guard that must stay stopped across a restart of the server
needs the unit switched off first
(`sudo systemctl disable provared-guard-boot.service`).

### A real upstream in place of the demonstration's tools

Before the first start, put settings of your own in
`guard-data/executor-http.json` (make the folder, owned by 10001, mode
700), starting from `executor-oauth.example.json`, and leave
`oauth.issuer` and `oauth.clients` written `<like this>`: the start fills
them in. The start then does not write the demonstration's settings. Put
the upstream's token file in `guard-data` too, mode 600, owned by 10001:
paths are read from the settings' folder. The start's steps then name your
agents and your tools' actions. The upstream is reached from inside the
container: an upstream on the same server is not at `127.0.0.1` there.
An upstream in a container on the recipe's network (a service added to
`compose.yaml`) would be reached by its service's name, as
`http://<name>:<port>/mcp`; this was not tried.
A local program in place of the upstream must be one the image can run.

### Trying a packed copy

In place of the version on npm, the build can take a packed copy of the executor
(`npm pack` in `mcp-executor/`). Beside `compose.yaml`, put the `.tgz` file
in a folder `pack/`, and write a file `compose.override.yaml`, which
`docker compose` reads with `compose.yaml`:

```yaml
x-packed: &packed
  additional_contexts:
    executor-file: ./pack
  args:
    EXECUTOR: file:/tmp/executor/provared-mcp-executor-0.5.1.tgz
services:
  folders:
    build: *packed
  guard:
    build: *packed
```

With a packed copy the build runs `npm install` in place of `npm ci`: it
writes the executor's entry in the image's lockfile afresh, for the packed
file and its hash, and keeps the library's entry, whose hash is still
checked. The lockfile beside `compose.yaml` is not changed.

**The lockfile's entries are npm's.** Both were made from npm after
`provared` 0.9.0 and `provared-mcp-executor` 0.5.1 were published, with the
hashes npm gives, and `npm ci` checks them. The release rule, in this order:

1. Publish `provared`, then `provared-mcp-executor`.
2. In this folder, `npm install --package-lock-only --ignore-scripts`;
   commit the lockfile.
3. `node tools/release/check-recipe-lock.mjs --registry`, from the top of
   the repository: it stops where a `package-lock.provisional.json` is
   beside the lockfile, or where the lockfile's hash for the executor is not
   the one `npm view provared-mcp-executor@0.5.1 dist.integrity` gives.
4. Only then cut the release tag that "Getting the recipe" points at.

### How the containers are held in

- No container runs as root but `folders`, which gets back only the two
  capabilities it needs to give the folders their owners and modes
  (`CHOWN`, `FOWNER`), has no network, and ends.
- The guard runs as user 10001, Caddy as user 10002. Each has every
  capability dropped, cannot gain privileges (`no-new-privileges`), and a
  read-only file system but for its own folders and a small `/tmp`. Caddy
  listens on 80 and 443 with no capability: its network lets an
  unprivileged user listen on ports from 80 up.
- Caddy's administration endpoint is off, so nothing in the shared network
  can change its settings; a change to the `Caddyfile` takes effect when
  Caddy is restarted. HTTP/3 is off, since its port (443 over UDP) is not
  opened.
- Limits for a server with 2 GB of memory: the guard 768 MB, one processor
  and 256 processes; Caddy 256 MB, half a processor and 128 processes.
  Each log is kept to three files of 10 MB.
- Both restart unless stopped (the update command's `docker compose up -d`
  starts them all the same, above, "Updates"). The guard is given 30
  seconds to stop, so that each call in flight is settled and receipted.

## What has been tried

The script `mcp-executor/test/recipe-compose/docker-check.sh`, outside
`npm test`, was run on one Windows computer, in Docker's Linux engine
(Docker 29.7.2, Compose 5.5.0), with the tags giving Node.js 24.22.3 and
Caddy 2.11.9 on 17 November 2026. It builds the guard's image from a packed
copy of this executor (the library's lockfile entry and hash kept, the
executor's written for the packed file), starts the three containers with a test domain and
Caddy's own certificate authority (`tls internal`) in place of a public
one, and signs the permission with the library's development stand-in for
a passkey. Then, through Caddy, with `curl --resolve`, it found: the 401
that names the metadata; the metadata; the owner's page's
`content-security-policy` and `referrer-policy`; the `Origin` reaching the
guard unchanged (its own passes, another, or the same with `:443`, is
refused); port 80 sending a browser on to https. It found the guard's port
answering neither from the Docker network nor on the Docker host, only
Caddy's 80 and 443 published, every file in `guard-data` the guard's
user's with mode 600 (folders 700; the start's mark a socket, 600),
Caddy's folders Caddy's user's, the image's own files 644 from copies of
mode 600, Caddy's 404 for `/provared` and under it, `owner` refused while
the guard runs and `owner --reset` done with it stopped, `check` run
through `docker compose run`, a second start beside the running guard
refused (code 2) with `owner --reset` refused by the running guard's mark
after it, and the guard answering again 20 to 50 seconds after Caddy was
restarted on its own (five runs), with
`owner --reset` refused by the start's mark in that time. It stopped both
containers and started them with `docker start`: Caddy first, both came
back; the guard first, the guard stayed stopped until the boot unit's
command ran, and then answered. It stopped Caddy for 45 seconds: the
guard stopped, Docker's one try to start it again failed ("cannot join
network namespace of a non running container"), and once Caddy was
started again the guard stayed stopped for the 60 seconds looked at, until
`docker compose up -d` started it. Its last run, on 20 November 2026,
passed 45 checks of 45.

Not tried: a real server, a publicly signed certificate, DNS, a firewall,
a reboot of the server or a restart of Docker itself (and so the order in
which Docker starts the two then), the boot unit under systemd, the
weekly timer, `npm ci` against 0.5.0 or 0.5.1 on npm
(published on 21 and 22 November 2026), a shallow clone of a tag (the `git tag -v` command
was run on a full clone, against `v0.8.0`), and claude.ai with this
recipe (the guard on its own was tried with claude.ai; see the start of
this README).

## The limits

- **Port 443 only.** claude.ai reaches a connector on port 443.
- **HTTPS from Caddy.** The guard speaks plain HTTP on 127.0.0.1. Caddy
  gives it HTTPS on port 443 at the address in `oauth.issuer`, with a
  certificate that a public authority signed, and passes the path and the
  `Origin` header on unchanged. Caddy needs port 80 open as well to get
  that certificate.
- **A public IPv4 address.** claude.ai connects from its own servers, over
  the internet, so Caddy must be reachable at a public IPv4 address.
- **The owner's passkey belongs to the public address.** The guard's page
  asks for the owner's passkey before a connection is approved (the
  guard's DESIGN.md, section 14.1). The passkey is tied to the host in
  `oauth.issuer`. If that address changes, the passkey no longer works
  there; the recovery code still approves a connection, and
  `owner --reset` makes a new owner at the new address. Where `.env`
  names another domain than the settings' `oauth.issuer`, the guard does
  not start, and its log says how to move.
- **Caddy restarted on its own.** The guard shares Caddy's network. Where
  Caddy's container is started again without the guard (a failure, or
  `docker compose restart caddy`), Caddy has a new network and the guard
  is left in the old one, where nothing reaches it. The start looks for
  Caddy's port every 5 seconds; after three misses it stops the guard,
  and Docker starts it again in Caddy's new network. Until then, about
  15 to 50 seconds (20 to 50 in the check's runs), claude.ai gets an
  error (502). A command that writes
  is refused in that time by the start's mark (above, "Commands, and the
  owner's reset"), not by the guard's lock, which it cannot see.
- **Caddy away for longer.** Where Caddy is not running when Docker starts
  the guard again (Caddy stopped for more than about 15 seconds, or ending
  again and again on a mistake in its Caddyfile), the guard cannot join
  Caddy's network, and Docker does not try again: the guard stays stopped
  after Caddy is back (the check below found this, with Caddy stopped for
  45 seconds). Run `docker compose up -d` in the folder of
  `compose.yaml` once Caddy runs.
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
  call. With this recipe, no passkey on a device (a computer's own, a
  phone, a security key) has been tried, and neither has claude.ai. The
  guard on its own was tried with both: a computer's own passkey and
  claude.ai (see the start of this README). The steps below try the real
  thing by hand.
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
  program that speaks it alone cannot be served. The one exception is
  the `initialize` that begins a session, which is taken whatever the
  header names; the log line of a refusal
  (`"code":"protocol-version"`) says which version was named. In front of an upstream
  HTTP server the header goes on to the upstream, which answers for it.
- **A tool's question needs the stream.** What a local program sends of
  its own (the progress of a call, a question a tool asks during it) goes
  on the session's GET stream. Where the client has none open it is
  dropped, and a call that waits for an answer to such a question ends at
  the guard's `timeout`.
- **The permission is a person's.** The recipe never signs a permission
  and never fills in a thumbprint: both come from the person, by hand.

## The files

- `compose/compose.yaml`, `compose/Dockerfile` (with
  `Dockerfile.dockerignore`), `compose/package.json` and
  `compose/package-lock.json`, `compose/Caddyfile`,
  `compose/example.env`: the recipe, as above.
- `compose/start.mjs`: the guard's first-start program, run in its
  container. It runs the guard's own commands and makes no request to
  anyone.
- `compose/weekly/`: the weekly timer, off until switched on.
- `compose/boot/`: the unit that starts the guard after a restart of the
  server, off until switched on.
- `executor-oauth.example.json`: settings for an upstream HTTP server of
  your own, with one agent kept for the connection (`claude-1`,
  `"oauth": true`). Put in the upstream's address and token file and,
  once the permission is signed, the passkey's thumbprint; the start
  fills in the issuer and claude.ai's document.

To let a second claude.ai connection in, add a second agent marked
`"oauth": true`. Each approved connection is one agent, with its own
permission and book. In this order the guard keeps running for the first
agent until the second is ready:

1. Add the agent in `guard-data/executor-http.json` (with its own `slip`,
   `book` and `keys`, and `issuerKeys` written `<like this>`). The
   running guard does not read the file again until it is started again.
2. `docker compose run --rm guard keys --out permission-entries-2.json`:
   it makes the new agent's key file, keeps the keys already there, and
   writes what each agent's permission must hold to that new file. It
   takes no lock, so it runs beside the guard. Read it with
   `sudo cat guard-data/permission-entries-2.json`.
3. Have the second permission signed, put it in place as for the first,
   and put the thumbprint in the agent's `issuerKeys`.
4. `docker compose restart guard`.

Where the guard is started again before the second permission is in
place, it waits for it, and the first agent's connection is down until
then. Where the file of entries does not name an agent that waits, or
its key file is not there, the start makes them, writes
`permission-entries.json` again for every agent, and keeps the file
before beside it as `permission-entries.before-<time>.json`.

## Trying the owner's passkey by hand

A passkey cannot be made at `http://127.0.0.1`: WebAuthn takes no IP
address as a passkey's site. So try it at Caddy's https address. Below,
`https://guard.example.com` stands for that address. The demonstration's
tools then show in claude.ai: `echo` with a text that holds the
lower-case word "password" is refused by the demonstration's rule on
content, and a denial is written; any other call to either tool gets a
receipt in `guard-data/books/connection-1.jsonl`.

1. Follow "The steps" above, to step 5: `check` lists no problem.
2. The start writes the owner's link,
   `https://guard.example.com/oauth/owner#…`, to
   `guard-data/owner-link.txt`, with the guard not yet running.
3. The start then starts the guard.
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
   `"by":"setup"`, and the state file (`guard-data/oauth-state.json`) has
   an `owner`. A tool call then gets a receipt in that agent's book. Note
   which browser and which place for the passkey worked.

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
     Chromium 153 gave it at the local address, but no other browser has
     been tried. Caddy was seen to pass `Origin` on unchanged in the
     Docker check. Look at the request's `Origin` in the browser's network
     view.
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
   new one takes its place. Press Continue, once, within the 5 minutes
   the page gives; the browser goes back
   to claude.ai (the log: `"owner-recovery-spent"`, then `"by":"recovery"`).
   The next authorisation page has no box for a code, and says that the
   code is spent. A new code comes from `owner --reset` and a new setup.
8. Look at the headers: `curl -sI https://guard.example.com/oauth/owner`
   shows `content-security-policy: default-src 'none'; script-src 'self';
   connect-src 'self'; form-action 'self'; frame-ancestors 'none';
   base-uri 'none'` and `referrer-policy: same-origin`. The browser's
   console on either page shows no blocked script.
9. To start again: reset the owner as "Commands, and the owner's reset"
   says. `owner --reset` says the owner was removed and how many
   connections ended. claude.ai must then connect again, with a new owner.
