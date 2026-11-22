# provared-shopify

A small MCP server for one Shopify store's Admin API, made to run behind
the Provared guard (`provared-mcp-executor`). An AI agent can list and
read products, change a variant's price, list, make and stop discount
codes, list and read orders, and refund part or all of an order. The
guard stands in front, checks each call against a permission a person
signed with a passkey, and writes a signed receipt.

Every amount of money and every percentage is one whole number at a
fixed place in a call's arguments, with its currency beside it, so that
the permission can limit it: "refunds at most 500 GBP a day", "no
discount above 30%".

**It has been run only against a made-up Shopify, in its tests. It has
not been tried against a real store.** Try it on a development store
before a real one.

It is not made, supported or approved by Shopify. It uses an app the
merchant makes for its own store and Shopify's published Admin API, and
nothing else.

*Evidence, not a verdict.*

## What it is

- One program, `server.mjs`, that speaks the Model Context Protocol
  (revision 2025-11-25) over its standard input and output. Four files,
  under 1,300 lines. It needs Node.js 24 and no other package.
- For one store, named in its settings, and one version of the Admin API
  (`2026-10`). Where Shopify answers with any other version, the server
  uses no answer and sends no change.
- It signs in with the app's client ID and client secret, keeps the
  access token in memory, and renews it before it expires.
- The only requests it makes are to that store's token address and Admin
  API. It sends nothing anywhere else and keeps no record of its own.
- A change is sent to Shopify once. The server never tries a refund, a
  price change or a discount code a second time.

`DESIGN.md` gives each name and fixed text as a numbered choice, with
its reason.

## The tools

| Tool | What it does | The amount a permission can limit |
|---|---|---|
| `list_products` | Lists products, each with its lowest and highest price | |
| `read_product` | One product and its variants, each with its price | |
| `set_variant_price` | Changes the price of one variant | `price_minor`, with `currency` |
| `list_discount_codes` | Lists discount codes, with the percentage or amount off | |
| `create_percentage_discount_code` | Makes a code that takes a percentage off | `percent`, from 1 to 100 |
| `create_amount_discount_code` | Makes a code that takes an amount of money off an order | `amount_minor`, with `currency` |
| `deactivate_discount_code` | Stops a code being used; Shopify keeps it | |
| `list_orders` | Lists orders, newest first, with totals | |
| `read_order` | One order: items, payments, refunds, what is paid and not refunded | |
| `refund_order` | Gives back part or all of what was paid on an order | `amount_minor`, with `currency` |

Money is a whole number of the currency's smallest unit: `1250` is 12.50
GBP, and `1250` is 1,250 JPY. A decimal is refused. The number of
decimal places of a currency is taken from ISO 4217; a currency the
server does not know is refused.

`currency` must be the shop's own, or for a refund the one the order was
paid in; the server asks Shopify which that is before it sends a change,
and refuses where they differ.

A refund always states its amount. To refund a whole order, read it and
give its `paid_and_not_refunded`. The money goes back to the payment it
came from; where an order has more than one payment, the call names one
with `transaction_id`. Nothing is put back into stock, and the customer
is told only where `notify` is true.

The answer to a refund says `done` only where Shopify reports the money
as sent: every payment of the refund succeeded, and they come to the
amount asked for. Where Shopify has recorded the refund and not yet
reported the money as sent, the answer says so under `not_confirmed`
and does not say `done`. Where Shopify reports that sending the money
failed, or reports another amount, the answer is an error that gives
Shopify's figure. Every figure in an answer is Shopify's, not the one
asked for.

Every answer to a refund that was sent to Shopify names its
`idempotency_key`, a failure too. Where the outcome of a refund is not
known, the same call sent again with that key (and every other argument
as it was) is, to Shopify, the same refund for 24 hours, and is not made
twice. Sent again without the key, it is a second refund.

The server reads the order before it sends anything, the second time as
the first. Where the first sending was in fact made and little or
nothing is left on the order, the server refuses the second call itself.
Its answer then does not say that nothing was refunded. It says that
this call sent no refund, and lists the order's refunds with their
amounts and times, which show whether the first was made.

A new discount code is likewise said to be made only where Shopify
reports it as asked for: its code, its limit on uses, its end and its
state. A code that starts later is said to give its discount from then.

No tool gives a customer's name, address, email or telephone number,
and the server asks Shopify for none of them. Nor can orders be looked
for by them: `list_orders` takes no search text, only these filters,
each from a fixed list or of a fixed form: `status`, `financial_status`,
`fulfillment_status`, `created_from`, `created_to`, `name` (an order's
name, such as #1001) and `test`. What a merchant has typed into a
product's title, a discount code or a refund's note is given as it is.

## The floor under a price

A permission's limits are ceilings: one can cap a price, and none can
stop a price being cut. So the server has a floor of its own, in its
settings, which no call can change:

| Setting | What it is | Unless given |
|---|---|---|
| `SHOPIFY_MIN_PRICE_MINOR` | The lowest price the server will set, a whole number of the currency's smallest unit | `1`: no price of nothing |
| `SHOPIFY_MAX_PRICE_CUT_PERCENT` | How far below the present price one call may set a price, a whole number from 0 to 100 | `0`: a price may be raised or left, and not lowered |

**With neither set, the agent cannot lower any price.** To let it, give
the largest cut: with `20`, a variant at 10.00 GBP can be set to 8.00
and no lower in one call. The present price is the one Shopify gives
just before the change. A refusal says the lowest price the server
would set now.

The cut is for each call. Five calls of 20% each bring 10.00 down to
3.28, so set the lowest price too, and have the permission limit how
many times the action may be taken:

```json
{ "action": "shopify.set_variant_price", "count": 5, "per": 86400 }
```

The lowest price is one figure for every product in the store. A value
that is not a whole number in its range stops the server from starting.

## The access the app needs

Three access scopes, and no other:

| Scope | For |
|---|---|
| `write_products` | Products and variants, and changing a variant's price |
| `write_discounts` | Discount codes: listing, making and stopping them |
| `write_orders` | Orders, and refunds |

In Shopify a write scope includes reading. Orders older than 60 days are
not reached: that would need `read_all_orders`, which is not asked for.

The server holds whatever access the app has, so give the app these
three and nothing more.

## Making the app in Shopify

This follows Shopify's documentation as it was on 14 November 2026. The
steps have not been walked through on a real store here; where the
screen differs, Shopify's own pages are right.

You need a Shopify user who may develop apps for the organisation.

1. In the Shopify admin, open **Settings**, then **Apps**, then
   **Develop apps**. This opens the Dev Dashboard.
2. On **Apps**, select **Create app**, then **Start from Dev
   Dashboard**. Name the app (for example "Provared guard") and select
   **Create**.
3. On the app's **Versions** page, leave the App URL as it is, and under
   **Scopes** enter `write_products,write_discounts,write_orders`. Select
   **Release**.
4. Open the app and select **Install app**. Choose your store and select
   **Install**. The app and the store must belong to the same Shopify
   organisation; Shopify refuses the sign-in otherwise.
5. In the app's **Settings**, copy the **Client ID** and the **Client
   secret**. There is no token to copy: the server asks for one itself,
   and Shopify gives one that lasts 24 hours.
6. On the server, in the folder of the guard's settings, put each in a
   file of its own that only the guard's user can read:

   ```
   shopify/shop            the part of the store's address before .myshopify.com
   shopify/client-id       the Client ID
   shopify/client-secret   the Client secret
   ```

   and, for the floor under a price (see above), two more, each holding
   one whole number:

   ```
   shopify/min-price-minor         the lowest price, in the smallest unit: 100 is 1.00 GBP
   shopify/max-price-cut-percent   the largest cut in one call: 0 for none, 20 for a fifth
   ```

Shopify recommends giving such an app a list of the addresses it may be
used from, so that a stolen token is refused anywhere else. Set it to
the address of the server the guard runs on.

## How the guard starts it

The package is on npm as `provared-shopify` (version 0.1.0, since
21 November 2026) and needs Node.js 24 and no other package. Put its files on the
server: unpack it from npm (`npm pack provared-shopify@0.1.0`, then
`tar -xzf` the file it names; the files are in `package/`), or copy the
folder `integrations/shopify` of the repository. The example below has
them in `/srv/provared-shopify`: move `package/`, or the copied folder,
there.

`executor-http.example.json` is an example of the guard's settings with
this server behind its front door for claude.ai, and
`content-rules.example.json` an example of its rules on content. Copy
them beside the guard's other files as `executor-http.json` and
`content-rules.json`, and put in each value written `<like this>`. The
part that starts this server:

```json
"server": {
  "command": "/usr/bin/node",
  "args": ["/srv/provared-shopify/server.mjs"],
  "env": {
    "SHOPIFY_SHOP": { "file": "shopify/shop" },
    "SHOPIFY_CLIENT_ID": { "file": "shopify/client-id" },
    "SHOPIFY_CLIENT_SECRET": { "file": "shopify/client-secret" },
    "SHOPIFY_MIN_PRICE_MINOR": { "file": "shopify/min-price-minor" },
    "SHOPIFY_MAX_PRICE_CUT_PERCENT": { "file": "shopify/max-price-cut-percent" }
  }
},
"shutdownWait": 95000
```

The guard reads the five files when it starts and hands their contents
to the server in its environment; the agent sees none of them and can
change none of them. The guard starts one server for each session and
ends it with the session. The last two lines of `env` may be left out;
the server then lowers no price. `shutdownWait` gives a server whose
session has ended 95 seconds to finish the call it has in hand: a little
more than the three requests a refund can take.

The part that says what each tool is, and where its amount is read:

```json
"tools": {
  "refund_order": { "action": "shopify.refund_order", "amount": { "unit": "GBP-pence", "pointer": "/amount_minor" } },
  "create_percentage_discount_code": { "action": "shopify.create_percentage_discount_code", "amount": { "unit": "percent", "pointer": "/percent" } }
}
```

The example names all ten tools, each with an action of its own
(`shopify.` and the tool's name). The permission the person signs then
names the actions the agent may take and their limits, for example:

```json
"actions": ["shopify.list_orders", "shopify.read_order", "shopify.refund_order", "shopify.create_percentage_discount_code"],
"limits": [
  { "action": "shopify.refund_order", "max": 50000, "per": 86400, "unit": "GBP-pence" },
  { "action": "shopify.create_percentage_discount_code", "each": 30, "unit": "percent" }
]
```

That is: refunds of at most 500.00 GBP in any 24 hours, and no discount
code above 30%. A tool whose action the permission does not name is
refused by the guard.

The unit is text that the rule and the limit must share. `GBP-pence` is
the example's; a shop in another currency writes its own. The example
rules on content refuse a call whose `currency` is not `GBP`, so that an
amount counted as pence is never an amount in another currency. Change
`GBP` there to the shop's currency.

The guard's own README (`mcp-executor/README.md`) says how to make its
keys, sign the permission and check the settings, and its recipe
(`mcp-executor/recipes/claude-ai/README.md`) how claude.ai connects to
it.

### Its settings, when started any other way

| Variable | What it is |
|---|---|
| `SHOPIFY_SHOP` | The store: the part of its address before `.myshopify.com` |
| `SHOPIFY_CLIENT_ID` or `SHOPIFY_CLIENT_ID_FILE` | The app's client ID, or the file that holds it |
| `SHOPIFY_CLIENT_SECRET` or `SHOPIFY_CLIENT_SECRET_FILE` | The app's client secret, or the file that holds it |
| `SHOPIFY_MIN_PRICE_MINOR` | The lowest price it will set; `1` unless given |
| `SHOPIFY_MAX_PRICE_CUT_PERCENT` | The largest cut in a price in one call, 0 to 100; `0` unless given |

Give one of each pair, not both. The server takes no setting from its
arguments, so a credential is never on a command line. It writes two
lines to its error output when it starts, naming the store, the version
of the Admin API and the floor under a price, and never the client
secret or a token.

Any other variable whose name begins `SHOPIFY_` stops the server from
starting, so that a setting whose name is misspelt is not passed over.
The guard hands the server only the variables its settings name.

## When something fails

A failure is told to the agent as a tool error, in a sentence that ends
by saying what became of the change:

- `Nothing was asked of the store.` The arguments were wrong, or the
  sign-in failed.
- `Nothing was changed.` or `Nothing was refunded.` The server refused
  before any change (the floor under a price among its reasons), the
  reading it makes before a change failed, or Shopify refused and gave
  no result. Shopify's reason is given in its own words.
- `The change was not made.` Shopify refused the request and gave no
  result: it is limiting the app's requests (its throttling answer), the
  app lacks an access scope, or the access token was not accepted.
- `Whether the change was made is not known.` Every other case: the
  connection failed, Shopify did not answer within 30 seconds, Shopify
  had an error of its own, its answer held an error beside a result, or
  another version of its Admin API answered. The sentence says what to
  read before trying again, and for a refund the `idempotency_key` to
  send it again with.

"Not made" is said only where it is known. The server does not try
again by itself in any of these cases. Whether to send a call again is
the agent's choice, and the guard counts a second call against the
permission as it counted the first.

After a change, an answer says `done` only where Shopify reports what
was asked for. Where it reports another price, percentage or amount, or
a stopped code as still active, the answer is an error that gives what
Shopify reports.

## Its limits

- **Tried only against a made-up server.** The tests run the server
  against `test/fake-shopify.mjs`, which answers in the forms Shopify's
  documentation gives. They show what the server sends and what it does
  with each answer. They do not show that a real store accepts it.
- It does not check the permission; the guard does. Started without the
  guard, it does what it is asked.
- A permission's limits are ceilings. They can cap a refund, a price or
  a percentage. They cannot stop a price being lowered; the server's own
  floor does that, with one lowest price for the whole store and a cut
  counted call by call. They do not say how much money a discount code
  goes on to give away.
- A refund that Shopify has recorded and not yet confirmed is reported
  as such, once. The server does not look again later; read the order.
- The server relies on Shopify naming the version that answered. An
  answer without that name is not used.
- An order paid in a currency other than the shop's own is not refunded
  here; refund it in the Shopify admin.
- A percentage is a whole number. A discount of 12.5% cannot be asked
  for.
- It makes no free-delivery or buy-one-get-one code, changes no code
  once made, and cancels, edits and fulfils no order.
- Orders older than 60 days are not reached.
- Shopify counts orders among the data that hold customers' details,
  and on a store that is not a development store it holds such details
  back from an app until the app is set up for them. This server asks
  for none of those details, but whether a real store then gives it
  orders with no further step has not been tried.
- The client secret is as safe as the file it is kept in and the server
  it runs on.

## Tests

```
npm test
```

In this folder, with Node.js 24. Nothing is installed. The tests start
the server as a program of its own, as the guard does, and a made-up
Shopify on the local address; no test reaches a real store or any other
computer.

## Licences

Copyright 2026 Pavel Izmaylov. The code: Apache License 2.0
(`LICENSE`). This document and `DESIGN.md`: Creative Commons Attribution
4.0 International (`LICENSE-CC-BY-4.0.txt`).
