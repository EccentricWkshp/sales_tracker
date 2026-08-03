# Shopify Integration

Two ways in, one import path. Both are implemented and both are off until you
turn them on in **Management**.

| | Date-range fetch | Webhooks |
| --- | --- | --- |
| Direction | Sales Tracker → Shopify | Shopify → Sales Tracker |
| Trigger | You click **Fetch Shopify Orders** | Order is placed / updated / fulfilled |
| Network | Outbound HTTPS only | **Requires a public HTTPS URL** |
| Latency | Whenever you run it | Seconds |
| Backfill | Yes — any date range | No, only from the moment you subscribe |
| Failure mode | You see the error immediately | Silent unless you check the log |

**Recommendation: run the date-range fetch as the system of record, and treat
webhooks as an optional convenience.** The reasoning is in "Should you enable
webhooks?" below. This is a LAN-only box, and exposing it to the internet is a
much bigger change than the feature is worth for most workflows.

---

## How duplicate detection works

Both paths converge on `import_processed_orders(..., source='shopify')`, which
matches an incoming order against `(source='shopify', external_order_id=<Shopify
order id>)`. Consequences worth knowing:

- **Webhook deliveries are at-least-once.** Shopify will re-send. A repeat
  updates the existing receipt instead of creating a second one.
- **Fetching a date range you already imported is safe.** Same key, same result.
- **A webhook and a later manual fetch of the same order produce one receipt.**
- **Line items are only built when the receipt is first created.** Re-importing
  an order updates its header (totals, tax, shipping, tracking, notes) and leaves
  line items alone, so corrections made by hand survive. If you need Shopify's
  line items back, delete the receipt and re-fetch.
- **The customer on an existing receipt is never reassigned**, so a manual
  customer merge is not undone by a re-import.

Orders that are cancelled or flagged `test` are skipped.

### Orders you already entered by hand

A sale typed in before the integration existed has no Shopify order id, so the
key above cannot see it — importing that date range used to write a second
receipt for a sale already on the books, and then ask you to pick a customer it
already had.

The import now recognises those. A hand-entered receipt is treated as the same
order when **its Order # matches and its date is within a day** of Shopify's.
Both are required: order numbers are not unique in this database, and other
platforms number orders in the same ranges, so the number alone would risk
welding two unrelated sales together. A date typed more than a day off is the one
case that still produces a duplicate — visible, and easy to delete.

On a match the receipt is **linked, not overwritten**:

- It keeps `source = 'manual'`. That is what marks it as yours, on this import
  and every later one — stamping it `shopify` would make the next run treat it as
  its own and rewrite your figures.
- **Total, tax, shipping and date stay exactly as you entered them.** Your
  numbers may already account for a discount or refund that the API still reports
  at face value.
- Empty fields are filled in — tracking, carrier and ship date if you left them
  blank. Anything you did record wins.
- It gains the Shopify order id, so it is matched by the reliable key from then
  on and can never be imported twice.
- A note records what happened, so a receipt that suddenly carries an order id is
  not a mystery.

The import summary counts these separately: *"3 order(s) you had already entered
by hand were matched to Shopify rather than duplicated."*

---

## Setup

### 1. Create the app in Shopify

Shopify offers two routes and **both are supported**. Pick one in Management →
Shopify → *Authentication Route*.

| | Legacy custom app | Dev Dashboard app |
| --- | --- | --- |
| Where | Admin → Settings → Apps and sales channels → Develop apps | Dev Dashboard |
| Credential | Admin API access token (`shpat_…`) | Client ID + client secret |
| Lifetime | Long-lived | Exchanged for a fresh 24-hour token |
| Webhook signing | API secret key | Client secret |
| Setup | Paste the token once | Paste the pair once; renewal is automatic |

Either way, grant these Admin API scopes:

| Scope | Why |
| --- | --- |
| `read_orders` | The orders themselves |
| `read_customers` | Buyer name/email/phone (see the PII section below) |
| `read_fulfillments` | Tracking number, carrier, ship date |
| `read_products` | Nicer product titles when a SKU is new |

> `read_orders` covers the last 60 days only. Importing older orders needs
> Shopify to grant `read_all_orders`, requested from the same Configuration
> screen. Without it, a wide date range returns fewer orders than you expect
> rather than erroring — check the count against the Shopify admin.

On the Dev Dashboard route, granting scopes takes **three** steps, and skipping
either of the last two is the most common way this integration fails:

1. Add the scopes to the app's **Configuration**.
2. **Release** that version. Configuration edits do nothing until released.
3. **Install** the app on the store, so the merchant approves the scopes.

An app that is installed but released without scopes still hands out access
tokens quite happily — they just carry no permissions. Sales Tracker now refuses
such a token at the exchange and names the missing scope, rather than letting it
fail later as a bare 403. If you see

```text
Shopify issued a token with no access scopes at all. Orders need read_orders.
```

you are missing step 1 or 2. If you see

```text
Shopify refused the request (403): [API] This action requires merchant approval
for read_orders scope.
```

the scopes are released but not approved — re-install the app on the store.
Either way, delete nothing here; the next fetch exchanges a fresh token
automatically.

On the **Dev Dashboard route**, the app exchanges your client ID and secret for
an access token the first time it fetches:

```text
POST https://{shop}.myshopify.com/admin/oauth/access_token
     grant_type=client_credentials&client_id=…&client_secret=…
  -> {"access_token": "shpat_…", "scope": "…", "expires_in": 86399}
```

That token is cached on the credentials row with its expiry and reused until five
minutes before it lapses, so a restart or a second import does not trigger a
fresh exchange. Changing the client ID or secret, or switching routes, clears the
cache. This flow is for apps on your own store — see
[Shopify's client secrets guide](https://shopify.dev/docs/apps/build/authentication-authorization/client-secrets).

### 2. Enter them in Sales Tracker

**Management** → Shopify:

- **Store Domain** — `your-store.myshopify.com`. The `.myshopify.com` host, not
  your customer-facing domain. A pasted full URL is trimmed to the host.
- **Authentication Route** — pick one; only that route's fields are shown.
- Legacy: **Admin API Access Token**, plus **API Secret Key** for webhooks.
- Dev Dashboard: **Client ID** and **Client Secret**.
- Tick **Enable Shopify integration** and save.

Saved secrets are never rendered back into the page. The fields show
`•••••••• (leave blank to keep)` — submitting them empty leaves the stored value
alone, so you can edit the store domain without re-pasting a token.

#### Credentials from the environment (development)

Any of these environment variables, typically from a `.env` file in the project
root, **overrides** the stored value. Management shows a *from environment* badge
on the fields they cover, so it is obvious why editing one has no effect.

| Variable | Field |
| --- | --- |
| `SHOPIFY_SHOP_DOMAIN` / `SHOPIFY_STORE_DOMAIN` | Store domain |
| `SHOPIFY_ADMIN_API_TOKEN` / `SHOPIFY_ACCESS_TOKEN` | Admin API access token |
| `SHOPIFY_API_SECRET` | API secret key |
| `SHOPIFY_CLIENT_ID` | Client ID |
| `SHOPIFY_CLIENT_SECRET` / `SHOPIFY_SECRET` | Client secret |
| `SHOPIFY_API_VERSION` | Admin API version |

`.env` is gitignored. The `enabled` switch still lives in the database, so tick
**Enable Shopify integration** once even when everything else comes from `.env`.

### 3. Import

A **Shopify** card appears on the dashboard. Pick a date range and click
**Fetch Shopify Orders**. It reports how many were created and updated, and lists
any individual orders that failed — one bad order no longer aborts the batch.

---

## Protected customer data, and the pending-order queue

Shopify treats a buyer's **name, email, phone and address** as *protected
customer data* (Level 2). For an admin-created custom app — which is what both
routes above produce — that access **depends on the store's plan**: Advanced and
Plus get it, lower plans do not. Nothing about the app configuration changes
this. Those fields simply come back `null`.

Everything else arrives intact: order number, date, totals, tax, shipping,
fulfillment tracking, and line items.

### What happens to such an order

It is **not** turned into a sale. It goes to **Sales → Pending Orders**, and
nothing about it counts toward any total until you complete it.

That is deliberate. A sale needs a customer, and the tax report reads the
customer's shipping address — `get_state_info` cannot classify an address with no
city or ZIP, so a half-identified sale would land silently in the `Unknown`
bucket and understate the WA figures with nothing on screen to say so. Parking
the order keeps the gap visible and the totals honest.

### Completing one

**Sales → Pending Orders** lists each parked order with its date, totals and line
items, plus a **location hint** — Shopify usually still returns `province_code`
and `country_code` even when it withholds the rest, so you often know the state
before you start. Look the order up in your Shopify admin (where you, as the
merchant, can see the buyer), then either:

- pick an **existing customer** from the dropdown, or
- fill in the **new customer** fields — the shipping address is pre-seeded with
  the location hint.

Click **Create Sale** and the order becomes an ordinary sales receipt: same
totals, same line items, a receipt number of its own, and an address the tax
report can read. The pending row is consumed.

**Discard** removes an order you do not want. Re-running the import for its date
range brings it back.

### Notes

- Re-imports and repeat webhook deliveries update a parked order in place; they
  never stack duplicates.
- If an order is already a completed sale, a later import updates its header
  normally — the queue is only for orders that have never had a customer.
- Upgrading the store plan does not retroactively fill in past sales. Re-fetch
  the date range to pick up details for orders still pending; sales already
  completed keep the customer you gave them.

---

## Should you enable webhooks?

Webhooks need Shopify's servers to reach this machine over HTTPS from the public
internet. That is the entire cost, and it is not small:

- Something must terminate TLS and forward to `192.168.1.194:4444` — a reverse
  proxy on a box with a real certificate, or a tunnel (Cloudflare Tunnel,
  ngrok, Tailscale Funnel).
- Whatever you expose is reachable by anyone who finds it. The app has one
  password and no rate limiting on `/login`. **Expose only `/shopify/webhook`,
  never the whole app.**
- Home broadband IPs change, and tunnels drop. When the URL breaks, Shopify
  retries for ~48 hours and then gives up — silently, as far as this app is
  concerned. Any order lost that way needs a manual date-range fetch anyway.

That last point is the crux: **you need the date-range fetch to be reliable
regardless, so webhooks only buy you latency.** For a business reconciling sales
daily or weekly for tax reporting, that latency is worth very little.

Enable them if you want the dashboard current without thinking about it, and you
already have a tunnel or proxy you trust.

### If you do enable them

1. Set the **API Secret Key** and tick **Accept inbound webhooks**.
2. Expose only the webhook path. Nginx, for example:

   ```nginx
   location = /shopify/webhook {
       proxy_pass http://192.168.1.194:4444/shopify/webhook;
       proxy_set_header Host $host;
       proxy_set_header X-Forwarded-Proto https;
   }
   location / { return 404; }
   ```

3. In Shopify admin → **Settings → Notifications → Webhooks**, add subscriptions
   pointing at `https://your-public-host/shopify/webhook`:

   | Topic | Why |
   | --- | --- |
   | `orders/create` | New orders |
   | `orders/updated` | Edits, refunds, address corrections |
   | `orders/fulfilled` | Tracking number and carrier |

   Format JSON, latest API version.

4. Send a test notification from Shopify and confirm it in
   `logs/sales_tracker.log`:

   ```text
   Shopify webhook orders/create: created 1, updated 0
   ```

### What the endpoint enforces

- **404 while disabled.** Until **Accept inbound webhooks** is ticked *and* an
  API secret is stored, the route does not exist — nothing to find by scanning.
- **HMAC on every request.** `X-Shopify-Hmac-Sha256` is checked against
  HMAC-SHA256 of the raw body using your API secret, compared with
  `hmac.compare_digest`. Verification happens before the body is parsed. A bad
  or missing signature is a 401 and a logged warning.
- **Shop domain pinning.** `X-Shopify-Shop-Domain` must match your configured
  store, so a signature from another store cannot write here.
- **Retry-friendly status codes.** 200 on success or a deliberately ignored
  order; 5xx if the database write failed, which is Shopify's cue to retry with
  backoff.

The signature *is* the authentication — there is no login on this route, by
necessity, because Shopify cannot log in.

---

## Field mapping

Three identifiers, three distinct jobs — they are not interchangeable:

| Sales Tracker | Shopify |
| --- | --- |
| `receipt_number` — shown as **Receipt #** | *nothing* — set to the receipt's own id, exactly as hand-entered sales are |
| `external_order_number` — shown as **Order #** | `name`, e.g. `#1001` |
| `external_order_id` — the re-import match key, not displayed | `id` (the numeric order id) |
| `source` | `'shopify'` |
| `date` | `created_at`, converted to **naive local time** |
| `total` | `total_price` |
| `tax` | `total_tax` |
| `shipping` | `total_shipping_price_set.shop_money.amount` |
| `shipservice` | first word of `fulfillments[-1].tracking_company`, uppercased |
| `tracking` | `fulfillments[-1].tracking_number` |
| `shipdate` | `fulfillments[-1].created_at` (date part) |
| `customer_notes` | `note` |
| Customer | `shipping_address`, falling back to `billing_address` |
| Line items | `line_items[].sku / title / quantity / price` |

Timestamps are converted to naive local time to match every other write path.
Storing tz-aware UTC alongside naive local values made sales sort incorrectly and
could push a sale into the neighbouring quarter on the state taxes report.

`province_code` is mapped to the customer's state, which is the USPS abbreviation
`get_state_info()` needs for WA B&O reporting.

---

## Known limitations

- **Refunds are not deducted.** `total_price` is the order as placed. A refunded
  order keeps its original total until you edit the receipt. Worth revisiting if
  refunds are common.
- **Multi-currency shops** import the shop-currency amount for shipping but the
  presentment amount for `total_price`/`total_tax`. Single-currency shops are
  unaffected.
- **Products are matched on SKU.** A Shopify line item with no SKU falls back to
  its title, which can create a product named after the product title. Set SKUs
  in Shopify.
- **Customer PII depends on the store plan**, not on anything configurable here —
  see the pending-order section above.
- **Only one store.** The credentials table holds a single row.
- **API version is pinned** to `2026-01` in `SHOPIFY_API_VERSION`, overridable
  with the environment variable of the same name. Shopify supports each version
  for 12 months — bump it roughly annually.
- **Paging stops at 100 pages** (25,000 orders) per fetch as a runaway guard;
  narrow the date range if you ever hit that.
