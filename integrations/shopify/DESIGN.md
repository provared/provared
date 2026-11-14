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
own store, and is small enough to read in full: four files, under 1,300
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
new random UUID unless the call gives one.** Shopify: the key is
required from version 2026-04, a random UUID is what it recommends, and
its page on idempotency writes the key as a variable of the request, as
here. The server itself never sends a request twice (S24), so by itself
the key only meets Shopify's rule; S39 is what makes it of use.

**S21. The server refuses a refund itself, before sending anything,
where the order was not paid in the shop's own currency, where Shopify
does not say that it can be refunded, where Shopify does not say in a
form the server can read how much is paid and not refunded, or where
the amount is more than that.** Plainest. The first is a limit of this
version: such an order is refunded in the Shopify admin. Where a figure
cannot be read the refund is not sent; nothing is assumed.

**S22. The customer is told of a refund only where `notify` is true.**
Plainest: nothing is sent to a customer that was not asked for.

**S23. A list gives 20 unless `first` says otherwise (1 to 50) and goes
on from `after`. `list_products` and `list_discount_codes` pass `query`
to Shopify as it is** (Shopify's search syntax); `list_orders` does not
(S36). **A product, a variant, a discount code, an order and a payment
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
- `Nothing was changed.` / `Nothing was refunded.` The server refused
  before any change; or the reading it makes before a change failed; or
  Shopify refused in its `userErrors` and its answer holds no result
  beside them.
- `The change was not made.` Shopify refused the request itself, and its
  answer holds no result: its throttling answer (`THROTTLED`, or HTTP
  429), a missing access scope (`ACCESS_DENIED`), or HTTP 400, 401, 402,
  403, 404 or 423.
- `Whether the change was made is not known.` followed by what to read
  before trying again. Everything else: the connection failed; Shopify
  gave no answer in 30 seconds; it answered with an error of its own
  (HTTP 500 and up, or any other error in its answer); it answered with
  any other HTTP status (202, 204, 408, 409 among them); an error or a
  `userErrors` entry stands beside a result in the same answer; or
  another version of the Admin API answered (S38).

A false "not made" invites a second refund, so it is said only where it
is known, and "not known" is said in every other case.

A tool that is not one of the ten is a JSON-RPC error (-32602), as the
protocol says.

**S26. The client secret and every access token of the run are taken out
of every text the server writes, and `[removed]` put in their place.**
Plainest. The server never writes them itself; this is for what Shopify
might repeat in an error or in a product's title. They are taken out of
Shopify's words before those are cut to length, so that none is cut in
two, and out of each text of an answer before it is written as JSON, so
that one holding a quote or a backslash is still found.

**S27. A cancellation stops nothing.** Plainest. A call that has begun is
finished and answered, so that the outcome of a change is always told.

**S28. An answer is one text holding JSON, with the names used in the
arguments** (`order_id`, `amount_minor`, `currency`). Plainest. Money is
shown three ways together: Shopify's decimal, the whole number, and the
currency. After a change, the server holds what Shopify reports against
what was asked. It says `done` only where they are the same; where they
differ the answer is a tool error that gives Shopify's figure, not the
one asked for (a price, a percentage, an amount off, a code that Shopify
still reports as active).

### Access, and what is left out

**S29. The app needs three access scopes: `write_products`,
`write_discounts` and `write_orders`.** Shopify: a write scope includes
the read scope, and these are the scopes its pages give for the queries
and changes in S13. `read_all_orders` is not asked for, so orders older
than 60 days are not reached.

**S30. Nothing about a customer is asked for: no name, address, email or
telephone number.** Plainest, and Shopify's terms ask an app to request
no more data than it needs. The tests look through every request for
those fields. Nor can an order be looked for by them (S36).

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

**S34. The example settings give the server 95 seconds to end
(`shutdownWait`), and a call 230 seconds (`timeout`).** Plainest: a
little more than the three requests a refund can take (a sign-in, the
reading of the order and the refund itself, 30 seconds each), so that a
change in hand when a session ends can be answered. It covers one call;
calls waiting their turn behind it are not answered. The second is the
figure of the guard's own recipe for claude.ai.

### After the review of 14 November 2026

**S35. A refund is said to be `done` only where Shopify reports the
money as sent.** Shopify: its page for a refund says that a refund's
being there does not show that the money went back, and that the state
of each of its transactions does. The refund's transactions are asked
for with it. Where every one is a refund (`REFUND`) with the state
`SUCCESS` and they come to the amount asked for, the answer says `done`
and gives `refunded`. Where one is `PENDING`, `AWAITING_RESPONSE` or
`UNKNOWN`, the answer has no `done` and no `refunded`; under
`not_confirmed` it says that the refund is recorded and the money not
yet reported as sent. Where one is `FAILURE` or `ERROR`, where Shopify
names no transaction or one that is not a refund, where an amount cannot
be read or is in another currency, or where its figures are not the
amount asked for (whatever the state), the answer is a tool error. Every
figure told is Shopify's, never the one asked for. Every one of these
names the refund, so that it can be found, and an answer that is not an
error gives the time Shopify made it (`made_at`).

**S36. `list_orders` takes no search text. Orders are found by seven
fixed filters: `status`, `financial_status`, `fulfillment_status`,
`created_from`, `created_to`, `name` and `test`.** Shopify's names and
values for the first three and its `created_at`, `name` and `test`
filters. Shopify's search for orders can also filter by a customer's
email, a customer's id and the last digits of a card, and a bare word
searches names; an agent could ask which orders match and work a value
out a little at a time. So the server writes the search text itself:
each value is one of a fixed list, a date and time, an order's name
(letters, digits and hyphens) or true or false, and none can hold a
space, a quote or a colon.

**S37. A line of input ends at a line feed and nowhere else.** The
protocol: one message to a line. One carriage return before the line
feed is dropped. A carriage return alone is white space inside a JSON
message, and U+2028 and U+2029 may stand inside its text; a reader that
ends a line at them reads one message as several, and a piece of it
could then be read as a call. The server's own few lines do the
splitting; Node.js's line reader is not used.

**S38. An answer that does not name version `2026-10` in its
`X-Shopify-API-Version` header is not used, and no change is sent once
that is so.** Shopify: when a version is no longer reachable it does not
refuse; it answers with another and names it in that header. Every tool
that makes a change makes a reading first, so the check comes before the
change: `set_variant_price` reads the variant, `refund_order` the order,
and the three discount-code tools the shop's currency. The server says
so on its error output. Where the change itself is answered by another
version, its outcome is said to be not known. An answer with no such
header is treated the same way.

**S39. `refund_order` takes an optional `idempotency_key`, and every
answer to a refund that was sent to Shopify names the key it was sent
with, a failure too.** Shopify: for 24
hours it treats two requests with one key as one refund and answers the
second with the first's outcome. So after "not known" the agent can send
the same call again with the key it was told, every other argument as it
was, and no second refund is made. Without the key, a second call is a
refund of its own; the server's check (S21) and the permission's limit
are then all that bound it. The key must be a UUID in lower case.

**S40. The server will not set a price below
`SHOPIFY_MIN_PRICE_MINOR`, a whole number of the currency's smallest
unit; 1 unless given.** Plainest and safest: a permission's limits are
ceilings, so nothing in the guard stops a price being cut, and the floor
is therefore the server's own setting, which no call can change. With
nothing set, no price can be made nothing.

**S41. One call may not set a price more than
`SHOPIFY_MAX_PRICE_CUT_PERCENT` per cent below the present price, a
whole number from 0 to 100; 0 unless given.** Plainest and safest: with
nothing set a price may be raised or left, and not lowered at all. The
present price is the one Shopify gives in the reading just before the
change. The lowest price allowed is worked in whole numbers and rounded
up, against the cut; where the present price cannot be read the change
is not sent. A setting that is not a whole number in its range stops the
start. The cut is for each call: a permission that allows several calls
allows several cuts, one after another, down to the lowest price, so a
permission should also limit how many times the action may be taken
(`{"action": "shopify.set_variant_price", "count": 5, "per": 86400}`).

**S42. Both settings are written at the start on the error output, and
the tool's description says that they exist.** Plainest: the agent can
see why a cut was refused, and the refusal gives the lowest price the
server would set now.

### After the second review of 14 November 2026

**S43. Where a call gives `idempotency_key` and the server itself
refuses it, the answer does not end "Nothing was refunded".** Plainest.
Such a call may be the second sending of a refund whose outcome was not
known. If the first was made, the order now has less left, and the
server's own check (S21) refuses the second before Shopify sees the key:
a whole order refunded, or more than half of what was left. "Nothing was
refunded" would then read as the first refund not having happened. So
the answer says `This call sent no refund`, that it may be a second
sending and that whether the first was made is not known to the server,
and lists the order's refunds as Shopify has just given them (each with
its amount and time), or says that the order has none. The server's
check is kept, not skipped for a call with a key: it does not rest on
what Shopify does with a key, which has not been tried.

**S44. A new discount code is said to be made only where Shopify reports
it as asked for: its code (in either case of letters), its limit on
uses, once for each customer, its end, its start where one was given,
and a state of `ACTIVE` or `SCHEDULED`.** Shopify's names for the
states. A difference is a tool error that lists each one. The answer
says "now gives" for an active code and "will give ... from" its start
for one that starts later. Two times are the same where they are the
same instant, however the zone is written.

**S45. What a reading gives is held against the id asked for, and an id
is written one way.** Plainest. Where Shopify answers the reading of a
variant, an order, a product or a discount code with another one, or
with none, nothing is changed and the answer says so. The number in an
id has no nought before it (`gid://shopify/Order/1001`, never
`.../01001`), so that a rule of the guard that names a thing by its
exact text matches every call for it.

**S46. A variable whose name begins `SHOPIFY_` and is not one of the
server's settings stops the start.** Plainest and safest: a misspelt
`SHOPIFY_MIN_PRICE_MINOR` would otherwise leave the lowest price at its
default without a word. Only the variable's name is said, never its
value. Started by hand on a computer whose environment holds other
`SHOPIFY_` variables, the server will not start until they are taken
out; the guard hands it only the variables its settings name.

## What it does not do

- It has not been tried against a real store.
- It does not check the permission. Started without the guard, it does
  whatever it is asked.
- It does not look for a member name given twice in a call's arguments;
  the guard refuses such a message before it arrives.
- A permission's limits are ceilings. A permission can cap a price but
  cannot stop a price being lowered; the server's own floor does that
  (S40, S41), with one lowest price for every product. A cap on a refund
  is on the amount, not on which order.
- A limit on `set_variant_price` or on a discount is on each call's
  figure. It says nothing of how much money a discount code goes on to
  give away: that depends on who uses it.
- It refunds no order paid in a currency other than the shop's own.
- It makes no free-delivery or buy-one-get-one code, changes no code once
  made, and cancels, edits and fulfils no order.
- It keeps no record of its own. The record is the guard's.
