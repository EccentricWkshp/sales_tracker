"""Create the pending_order table.

Holds imported orders that arrived without buyer details, so they can be
completed by hand instead of becoming half-identified sales.

Shopify only shares a customer's name, email, phone and address with apps
approved for protected customer data; for an admin-created custom app that
depends on the store's plan. An order without them still has usable money and
line items, but no one to attach them to — and an address with no city or ZIP
cannot be classified by `get_state_info`, so the sale would land silently in the
'Unknown' bucket and understate the WA totals.

Nothing in this table counts toward any total. Completing a row (Sales →
Pending Orders) creates the real sales receipt and deletes the pending row.

Usage: python migrations/add_pending_orders.py [path-to-db]
Defaults to instance/sales.db. Safe to run more than once.
"""
import os
import sqlite3
import sys

db_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'instance', 'sales.db')

if not os.path.exists(db_path):
    raise SystemExit(f"Database not found: {db_path}")

conn = sqlite3.connect(db_path)
try:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_order (
            id INTEGER NOT NULL PRIMARY KEY,
            source VARCHAR(20) NOT NULL,
            external_order_id VARCHAR(64) NOT NULL,
            external_order_number VARCHAR(50),
            order_date DATETIME,
            total FLOAT NOT NULL DEFAULT 0,
            tax FLOAT NOT NULL DEFAULT 0,
            shipping FLOAT NOT NULL DEFAULT 0,
            shipservice VARCHAR(50),
            tracking VARCHAR(50),
            shipdate DATE,
            customer_notes VARCHAR(500),
            internal_notes VARCHAR(500),
            payload TEXT NOT NULL DEFAULT '{}',
            imported_at DATETIME,
            CONSTRAINT uq_pending_order_source_ext UNIQUE (source, external_order_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS ix_pending_order_source "
                 "ON pending_order (source)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_pending_order_external_order_id "
                 "ON pending_order (external_order_id)")
    conn.commit()

    rows = conn.execute("SELECT COUNT(*) FROM pending_order").fetchone()[0]
    print(f"{db_path}: pending_order ready ({rows} row(s) waiting)")
finally:
    conn.close()
