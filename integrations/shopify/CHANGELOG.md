# Changelog: provared-shopify

## 0.1.0 (not yet released)

The first version. It has been run only against a made-up Shopify, in
its tests; it has not been tried against a real store.

- **An MCP server for one Shopify store's Admin API**, over standard
  input and output (protocol revision 2025-11-25; the two revisions
  before it are answered where a client asks for them). Written by hand
  on Node.js 24, with no other package. It is made to be started by
  `provared-mcp-executor`, which checks each tool call against a signed
  permission and writes a signed receipt.
- **Ten tools:** `list_products`, `read_product`, `set_variant_price`,
  `list_discount_codes`, `create_percentage_discount_code`,
  `create_amount_discount_code`, `deactivate_discount_code`,
  `list_orders`, `read_order` and `refund_order`. Each schema names every
  argument it takes; a call with any other is refused.
- **Money and percentages as whole numbers at fixed places.** A price is
  `price_minor`, an amount off or a refund is `amount_minor` (the
  currency's smallest unit, by ISO 4217), each with a `currency` that
  must be given; a percentage is `percent`, from 1 to 100. The guard's
  rule for a tool can therefore read the amount, and a permission can
  limit it. A currency the server does not know, or one that is not the
  shop's own (for a refund, the order's), is refused before anything is
  sent.
- **Sign-in by the app's client ID and secret** (Shopify's client
  credentials grant), each read from the environment or from a file
  named there, never from an argument. The access token is kept in
  memory and renewed when it has a minute or less left. The Admin API
  version is fixed at `2026-10`.
- **A change is sent once.** Nothing is tried again after Shopify's
  throttling answer, an error, a lost connection or no answer in time. A
  query answered 401 is sent once more with a new token; a change
  answered 401 is not. `refundCreate` is sent with an idempotency key,
  new for each request, as Shopify requires.
- **Failures as MCP tool errors in plain words**, each ending with what
  became of the change: nothing asked, nothing changed, the change not
  made, or its outcome not known and what to read before trying again.
- **The client secret and every access token are taken out of
  everything the server writes**, whatever Shopify repeats in an answer.
- **Three access scopes:** `write_products`, `write_discounts` and
  `write_orders`. Nothing about a customer is asked for.
- **Examples for the guard:** `executor-http.example.json` (its settings,
  starting this server behind its front door for claude.ai, with one
  action for each tool and the amount where there is one) and
  `content-rules.example.json` (rules that fix the currency of each tool
  that carries money).
- **Tests** (`npm test`, 78 tests): the protocol, the sign-in and its
  renewal, a token that stops working mid-session, each tool, calls
  handled one at a time, a refused refund, Shopify's throttling answer,
  failures with the outcome unknown, a redirect not followed, the client
  secret in no output, the conversion of money, the examples held
  against the server, each finding of the review below, and the floor
  under a price. A job in the repository's tests workflow
  (`integrations/shopify`) runs them.
- `DESIGN.md` gives each tool name, action name and fixed text as a
  numbered choice (S1 to S42), with where it comes from.

### Changed after an independent review, before any release

Each was a fault in the first build; each has a test that fails without
the change.

- **A refund's answer says what Shopify reports of the money.** The
  first build said "was refunded" as soon as Shopify gave back a refund.
  The refund's own transactions are now asked for with it. The answer
  says `done` only where every one succeeded and they come to the amount
  asked for; a refund not yet confirmed is told under `not_confirmed`; a
  failed one, or one for another amount, is a tool error that gives
  Shopify's figure.
- **A line of input ends at a line feed alone.** Node.js's line reader
  also ended a line at a bare carriage return and at U+2028 and U+2029,
  so one valid message could be read as several, and a piece of it as a
  call: a refund hidden between two carriage returns in another call was
  made. The server now splits its input itself.
- **"The change was not made" and "Nothing was changed" are said only
  where that is known.** Not where an error (`THROTTLED`,
  `ACCESS_DENIED`) or a `userErrors` entry stands beside a result in the
  same answer, and not for an HTTP status that is neither Shopify's
  answer nor one of its refusals (202, 204, 408, 409): those now say
  that the outcome is not known.
- **`list_orders` takes no search text.** It passed the agent's `query`
  to Shopify, whose search can find orders by a customer's email, id or
  card. It now takes seven fixed filters (`status`, `financial_status`,
  `fulfillment_status`, `created_from`, `created_to`, `name`, `test`)
  and writes the search text itself.
- **The version of the Admin API that answered is checked.** An answer
  whose `X-Shopify-API-Version` header is not `2026-10` is not used, and
  every tool that makes a change makes a reading first, so no change is
  sent once Shopify answers with another version.
- **A floor under a price**, in the server's own settings, which no call
  can change: `SHOPIFY_MIN_PRICE_MINOR` (1 unless given) and
  `SHOPIFY_MAX_PRICE_CUT_PERCENT` (0 unless given, so a price may be
  raised and not lowered). The cut is held against the price Shopify
  gives just before the change.
- **`refund_order` takes an optional `idempotency_key`**, and every
  answer to a refund names the key it was sent with, so that a refund
  whose outcome is not known can be sent again without being made twice.
- **Smaller points.** A secret that Shopify repeats is taken out before
  its words are cut to length, and out of each text before an answer is
  written as JSON. A reading that fails before a change says that
  nothing was changed. After a price change, a discount code or the
  stopping of one, `done` is said only where Shopify reports what was
  asked for. A refund is not sent where the server cannot read how much
  is paid and not refunded, or whether the order can be refunded. The
  example gives the server 95 seconds to end, not 35. The documents give
  the server's size as it is (under 1,200 lines).
