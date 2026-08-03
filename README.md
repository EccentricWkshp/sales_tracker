# sales_tracker

A small Flask app for a single business: imports orders from shipping platforms
and storefronts, tracks customers and products, produces sales receipts and
invoices, and totals revenue for WA state tax reporting.

Runs on the LAN — the server binds `0.0.0.0:4444` so other machines can reach it.

## Order sources

| Source | Status |
| --- | --- |
| **Shopify** | Date-range fetch **and** HMAC-verified webhooks — see [integrations-shopify.md](integrations-shopify.md) |
| **ShipStation** | Date-range fetch. ShipStation's June 2025 API changes require a higher plan tier; this integration will stop working at some point |
| **Shippo** | Date-range fetch |
| **WooCommerce** | Credentials and UI only — the importer is not written yet |

Each is off until enabled in **Management**, and only enabled sources appear on
the dashboard.

## Setup

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
flask create-admin
```

Then start it with **Start Sales Tracker.bat**, or `venv\Scripts\python app.py`.
Both use port 4444 and serve through waitress. Open `http://<this-machine>:4444/`.

Enter company details and any API credentials on the **Management** page.

### Configuration

Everything has a working default; set these only if you need to change one.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `FLASK_SECRET_KEY` | generated once into `instance/secret_key` | Signs session cookies |
| `SALES_TRACKER_HOST` | `0.0.0.0` | Bind address |
| `SALES_TRACKER_PORT` | `4444` | Port |
| `SALES_TRACKER_DATABASE_URI` | `sqlite:///sales.db` | Database, relative to `instance/` |
| `SALES_TRACKER_BACKUP_RETAIN` | `14` | Backups kept |
| `SESSION_COOKIE_SECURE` | off | Set to `1` when serving behind HTTPS |
| `SHOPIFY_API_VERSION` | `2026-01` | Shopify Admin API version |

A `.env` file in the project root is loaded at startup if present, so
development credentials do not have to go through the Management page. Anything
already exported wins over the file, and `.env` is gitignored. Shopify's
credential variables are listed in
[integrations-shopify.md](integrations-shopify.md).

Windows uses `set VAR=value` (or `$env:VAR = 'value'` in PowerShell), not
`export`.

The secret key is generated on first run and persisted, so restarts do not log
you out. Keep `instance/secret_key` out of version control — `instance/` is
already ignored.

## Backups

The database is snapshotted to `instance/backups/sales-YYYYMMDD-HHMMSS.db` on
every app start, keeping the newest 14. Snapshots use SQLite's online backup API,
so they are consistent even while the app is serving.

For installs that stay up for weeks, point Windows Task Scheduler at
**Backup Sales Tracker.bat**, or run it directly:

```bat
venv\Scripts\python migrations\backup_db.py
```

It also reports `PRAGMA quick_check` and any foreign-key orphans.

To restore, stop the app and copy a snapshot over `instance/sales.db`.

## Database migrations

Schema changes are hand-written, idempotent scripts in `migrations/`. Run them
against a stopped app, after taking a backup:

```bat
venv\Scripts\python migrations\add_receipt_source.py
venv\Scripts\python migrations\add_shopify_credentials.py
venv\Scripts\python migrations\add_pending_orders.py
venv\Scripts\python migrations\rename_order_identifier_columns.py
```

Each prints what it changed and is safe to run more than once.

Two one-off repair scripts are also there, both defaulting to a dry run:

```bat
venv\Scripts\python migrations\fix_imported_receipt_numbers.py --dry-run
venv\Scripts\python migrations\cleanup_placeholder_customers.py
```

## Identifiers on a sale

Three fields that are easy to confuse, and must not be used interchangeably:

| Field | Shown as | Meaning |
| --- | --- | --- |
| `receipt_number` | Receipt # | Sales Tracker's own receipt number — always the receipt's id |
| `external_order_number` | Order # | The selling platform's order number. Display only |
| `external_order_id` | *not shown* | The platform's internal order id; the key that matches a re-imported order to its existing receipt |

The first two were called `order_number` and `shipstation_order_id` until
2026-08-02. The old names dated from when ShipStation was the only import route
and became misleading once Shippo and Shopify wrote to the same columns —
`migrations/rename_order_identifier_columns.py` performs the rename, and
**a database restored from a backup taken before then needs it re-run**.

## Pending orders

Shopify only shares a buyer's name, email, phone and address with apps approved
for protected customer data, which for a custom app depends on the store's plan.
Orders that arrive without those details are held in **Sales → Pending Orders**
rather than becoming half-identified sales, and count toward no total until you
supply the customer. See [integrations-shopify.md](integrations-shopify.md).

## Notes

- Foreign keys are enforced and journaling is WAL. WAL is written into the
  database file the first time the app opens it, so a copied `.db` may be
  accompanied by `-wal` and `-shm` files; copy all three, or stop the app first.
- Money on `sales_receipt` and `line_item` is still stored as `FLOAT`. Product
  prices are `Numeric`. Converting the rest is a pending migration.
- Logs rotate in `logs/sales_tracker.log`.
