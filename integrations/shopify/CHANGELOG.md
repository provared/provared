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
- **Tests** (`npm test`, 50 tests): the protocol, the sign-in and its
  renewal, a token that stops working mid-session, each tool, calls
  handled one at a time, a refused refund, Shopify's throttling answer,
  failures with the outcome
  unknown, a redirect not followed, the client secret in no output, the
  conversion of money, and the examples held against the server. A job
  in the repository's tests workflow (`integrations/shopify`) runs them.
- `DESIGN.md` gives each tool name, action name and fixed text as a
  numbered choice (S1 to S34), with where it comes from.
