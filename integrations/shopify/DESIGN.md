# provared-shopify: the design, and the choices made

This is what the server does and why, with each name and fixed text it
uses as a numbered choice (S1 onward). Each choice says where it comes
from: **Shopify** means Shopify's public developer documentation
(shopify.dev), read on 14 November 2026; **the guard** means
`provared-mcp-executor` as it is in this repository; **plainest** means
the design fixed nothing and the simplest option was taken.

The server has been run only against a made-up Shopify
(`test/fake-shopify.mjs`). Nothing here has been tried against a real
store. Where this document says what Shopify does, it repeats Shopify's
documentation.

## What it is for

Shopify's own MCP server for a store accepts only clients Shopify has set
up, so the guard cannot stand in front of it. This server reaches the
same store through the Admin API, with an app the merchant makes for its
own store, and is small enough to read in full: four files, under 900
lines, no package but Node.js itself.

The guard starts it, one for each session, and stands between it and the
agent. The agent never sees the app's client secret or an access token.
The guard checks each tool call against the permission, reads the call's
amount from its arguments, and writes a signed receipt. This server does
the part the guard cannot: it holds the credential, talks to Shopify, and
gives each call a shape the guard can check.

## The shape of a call

A Provared permission limits whole numbers: "at most 50,000 in any
86,400 seconds", "no more than 30 each". The guard reads a call's amount
as the whole number at one place in its arguments, and refuses the call
where it finds anything else there. So:

- every argument that carries money or a percentage is one whole number,
  at the top of the arguments, under a name that does not change;
- it must be given, so the guard always finds it;
- no tool has two of them, because the guard's rule for a tool reads one;
- no other argument can change how much money moves: a schema names every
  argument, and a call with one it does not name is refused.

## The choices

### Names and settings

**S1. The package and the program are `provared-shopify`; the program is
`server.mjs`.** Plainest: the name of the library and the platform, as
`provared-claude-code`.

**S2. The settings are `SHOPIFY_SHOP`, `SHOPIFY_CLIENT_ID` and
`SHOPIFY_CLIENT_SECRET`.** Shopify: the names its tutorial for this
sign-in uses. `SHOPIFY_SHOP` is the part of the store's address before
`.myshopify.com`, as there. They are read from the environment and never
from the arguments: an argument other than `--version` or `--help` stops
the start.

**S3. The client ID and the client secret may each be given as the file
that holds it: `SHOPIFY_CLIENT_ID_FILE`, `SHOPIFY_CLIENT_SECRET_FILE`.**
Plainest: the setting's name with `_FILE`. Exactly one of the pair is
taken; both stop the start. The guard reads a credential from a file
named in its own settings and hands the server the value, so behind the
guard the plain names are used; started any other way, the `_FILE` names
keep the secret out of the environment. One line ending at the end of
the file is dropped, as the guard does. A value must be 1 to 512
printable characters with no space. Once read, the plain variables are
taken out of the server's own environment.

**S4. The Admin API version is `2026-10`, and no setting changes it.**
Shopify: the latest stable version on 14 November 2026, supported until
16 October 2027. A later version is a change to this package, tested
again.

**S5. `SHOPIFY_TEST_ORIGIN` puts a made-up server in Shopify's place,
and is taken only as `http://127.0.0.1:<port>`.** Plainest, and the
guard's own rule for an address without HTTPS. Any other value stops the
start, so the setting cannot send the client secret to another computer.
The server says on its error output that it is running against a made-up
server.

### Signing in

**S6. The sign-in is the client credentials grant: a POST to
`https://<shop>.myshopify.com/admin/oauth/access_token` with
`grant_type=client_credentials`, `client_id` and `client_secret` as a
form, and no `scope`.** Shopify. The answer's `access_token` goes in the
`X-Shopify-Access-Token` header of each request to
`https://<shop>.myshopify.com/admin/api/2026-10/graphql.json`. Shopify.

**S7. The token is kept in memory only, and renewed when it has 60
seconds or less left.** Shopify's example renews at 60 seconds. The
first sign-in is made when the first tool is called, not at the start,
so `initialize` and `tools/list` reach no network.

**S8. A redirect is never followed, and a request is given 30 seconds.**
Plainest. A redirect could carry the secret or the token to another
address.

### Money and percentages

**S9. Money is a whole number of the currency's smallest unit, under
`price_minor` or `amount_minor`, with `currency` beside it; both must be
given.** The format and the guard: an amount is a whole number, and the
guard refuses a call whose amount is anything else, so a decimal such as
12.50 could not be limited at all. 1250 is 12.50 GBP. "Refunds at most
500 GBP a day" is the limit `{"action": "shopify.refund_order", "max":
50000, "per": 86400, "unit": "GBP-pence"}`.

**S10. How many decimal places a currency has is taken from ISO 4217.**
A published standard. The table is in `money.mjs`. A currency not in it
is refused, not guessed: a wrong guess would move a decimal point. The
whole number is turned into Shopify's decimal string, and back, with no
floating-point arithmetic and no rounding.

**S11. `currency` must be the shop's own (for a price or a money-off
code) or the one the order was paid in (for a refund), and the server
asks Shopify which that is before it sends the change.** Plainest. So
the amount means what it says, and a rule of the guard that fixes
`/currency` (`content-rules.example.json`) makes the unit in a receipt
true.

**S12. A percentage is a whole number from 1 to 100 under `percent`.**
The format and the guard, as S9. It is sent to Shopify as `percent /
100`; Shopify takes a number from 0 to 1. "No discount above 30%" is the
limit `{"action": "shopify.create_percentage_discount_code", "each": 30,
"unit": "percent"}`. A fraction of a percent cannot be asked for.

### The tools

**S13. Ten tools, named by what they do.** Plainest: a verb and
Shopify's own word for the thing (product, variant, discount code,
order). `deactivate` is Shopify's verb (S16).

| Tool | Action | Amount | What Shopify is asked |
|---|---|---|---|
| `list_products` | `shopify.list_products` | | `products` |
| `read_product` | `shopify.read_product` | | `product`, `shop` |
| `set_variant_price` | `shopify.set_variant_price` | `/price_minor` | `productVariant`, `shop`; then `productVariantsBulkUpdate` |
| `list_discount_codes` | `shopify.list_discount_codes` | | `codeDiscountNodes` |
| `create_percentage_discount_code` | `shopify.create_percentage_discount_code` | `/percent` | `discountCodeBasicCreate` |
| `create_amount_discount_code` | `shopify.create_amount_discount_code` | `/amount_minor` | `shop`; then `discountCodeBasicCreate` |
| `deactivate_discount_code` | `shopify.deactivate_discount_code` | | `discountCodeDeactivate` |
| `list_orders` | `shopify.list_orders` | | `orders` |
| `read_order` | `shopify.read_order` | | `order` |
| `refund_order` | `shopify.refund_order` | `/amount_minor` | `order`; then `refundCreate` |

**S14. An action is `shopify.` and the tool's name, one for each tool.**
Plainest: one rule to remember, and a permission can allow each tool by
itself.

**S15. Making a discount code is two tools, not one.** The guard: its
rule for a tool reads one amount at one place. One tool taking either a
percentage or an amount of money would have two.

**S16. Stopping a discount code is `deactivate_discount_code`, through
Shopify's `discountCodeDeactivate`.** Shopify: its name, and its
meaning. The code is kept and can be turned on again in the Shopify
admin; nothing is removed.

**S17. A discount code made here is for every buyer and every product**
(`context: {all: ALL}`, `items: {all: true}`), **an amount of money is
taken off the order once, not off each item** (`appliesOnEachItem:
false`), **and it starts now unless `starts_at` says otherwise.**
Plainest. The optional arguments are `title` (the code itself where left
out), `starts_at`, `ends_at`, `usage_limit` and `once_per_customer`
(false where left out).

**S18. A refund always states its amount.** The guard: a refund of "all
of it" with no number could not be limited. To refund a whole order the
agent reads it and gives its `paid_and_not_refunded`.

**S19. A refund is one `REFUND` transaction against the payment it gives
back, sent with `refundCreate`.** Shopify: the form of its example with
a transaction. The server reads the order first and takes the payment's
id and gateway from it. Where the order has one successful payment (a
`SALE` or a `CAPTURE` with status `SUCCESS`) that is the one; where it
has more, the call must name one with `transaction_id`. No item is put
back into stock, no delivery charge is singled out, and
`allowOverRefunding` is never sent.

**S20. `refundCreate` is sent with `@idempotent(key: ...)`, the key a
new random UUID for each request.** Shopify: the key is required from
version 2026-04, and a random UUID is what it recommends. The key is
never used twice, because the request is never sent twice (S24).

**S21. The server refuses a refund itself, before sending anything,
where the order was not paid in the shop's own currency, where Shopify
says it cannot be refunded, or where the amount is more than was paid and
not refunded.** Plainest. The first is a limit of this version: such an
order is refunded in the Shopify admin.

**S22. The customer is told of a refund only where `notify` is true.**
Plainest: nothing is sent to a customer that was not asked for.

**S23. A list gives 20 unless `first` says otherwise (1 to 50), goes on
from `after`, and passes `query` to Shopify as it is** (Shopify's search
syntax). **A product, a variant, a discount code, an order and a payment
are named by Shopify's full id** (`gid://shopify/Order/123`).
Plainest. Orders come newest first.

### Changes, failures and what is said

**S24. A change is sent once.** The rule the server was built to: a
refund or a price change must never happen twice because the server
tried again. Nothing is tried again after
Shopify's throttling answer, an error, a lost connection or no answer in
time. A query that Shopify answers 401 is sent once more with a new
token; a change that it answers 401 is not: the token is dropped, the
call fails, and the next call signs in again. Tool calls are handled one
at a time, in the order they arrive.

**S25. A failure is an MCP tool error (`isError: true`) in a sentence,
and it ends by saying what became of the change.** Plainest. The fixed
endings:

- `Nothing was asked of the store.` The arguments were wrong, or the
  sign-in failed.
- `Nothing was changed.` / `Nothing was refunded.` The server, or
  Shopify in its `userErrors`, refused before any change.
- `The change was not made.` Shopify refused the request itself: its
  throttling answer (`THROTTLED`, or HTTP 429), a missing access scope
  (`ACCESS_DENIED`), or HTTP 401, 402, 404, 423 or another answer in
  the 400s.
- `Whether the change was made is not known.` followed by what to read
  before trying again. The connection failed, Shopify gave no answer in
  30 seconds, or it answered with an error of its own (HTTP 500 and up,
  or any other error in its answer).

A tool that is not one of the ten is a JSON-RPC error (-32602), as the
protocol says.

**S26. The client secret and every access token of the run are taken out
of every text the server writes, and `[removed]` put in their place.**
Plainest. The server never writes them itself; this is for what Shopify
might repeat in an error or in a product's title.

**S27. A cancellation stops nothing.** Plainest. A call that has begun is
finished and answered, so that the outcome of a change is always told.

**S28. An answer is one text holding JSON, with the names used in the
arguments** (`order_id`, `amount_minor`, `currency`). Plainest. Money is
shown three ways together: Shopify's decimal, the whole number, and the
currency. After a change, the server holds what Shopify reports against
what was asked, and says so under `warning` where they differ.

### Access, and what is left out

**S29. The app needs three access scopes: `write_products`,
`write_discounts` and `write_orders`.** Shopify: a write scope includes
the read scope, and these are the scopes its pages give for the queries
and changes in S13. `read_all_orders` is not asked for, so orders older
than 60 days are not reached.

**S30. Nothing about a customer is asked for: no name, address, email or
telephone number.** Plainest, and Shopify's terms ask an app to request
no more data than it needs. The tests look through every request for
those fields.

**S31. The server answers `initialize` with the protocol version asked
for where that is 2025-11-25, 2025-06-18 or 2025-03-26, and with
2025-11-25 otherwise.** The protocol: a server answers the version asked
for where it speaks it. It is written to 2025-11-25; what it sends for
tools (a name, a description, a schema, annotations, a text and
`isError`) is the same in the two before.

### The guard's settings

**S32. The example unit for money is `GBP-pence`, and for a percentage
`percent`.** Plainest. A unit is text the permission and the rule must
share, at most 16 characters; a shop in another currency writes its own
(`EUR-cents`, `JPY`).

**S33. The example rules on content fix `/currency` to `GBP` for the
three tools that carry money.** The guard. Without them the unit in a
rule is only a label; with them a call in another currency is refused
before it reaches this server.

**S34. The example settings give the server 35 seconds to end
(`shutdownWait`), and a call 230 seconds (`timeout`).** Plainest: a
little more than one request to Shopify, so that a change in hand when a
session ends can be answered; the second is the figure of the guard's
own recipe for claude.ai.

## What it does not do

- It has not been tried against a real store.
- It does not check the permission. Started without the guard, it does
  whatever it is asked.
- It does not look for a member name given twice in a call's arguments;
  the guard refuses such a message before it arrives.
- A permission's limits are ceilings. A permission can cap a price but
  cannot stop a price being lowered, and a cap on a refund is on the
  amount, not on which order.
- A limit on `set_variant_price` or on a discount is on each call's
  figure. It says nothing of how much money a discount code goes on to
  give away: that depends on who uses it.
- It refunds no order paid in a currency other than the shop's own.
- It makes no free-delivery or buy-one-get-one code, changes no code once
  made, and cancels, edits and fulfils no order.
- It keeps no record of its own. The record is the guard's.
