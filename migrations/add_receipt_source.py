"""Add source + external_order_id to sales_receipt so re-imports match reliably.

Why this is needed
------------------
Imports used to find an existing sale with
``SalesReceipt.query.filter_by(order_number=...)``. That is ambiguous in the
live data: `order_number` already contains two different things — the
marketplace order number on imported rows, and the receipt's own id on rows
created by hand in the Add Sale modal (`add_sale` sets
``order_number = new_sale.id``). The database currently holds duplicate
`order_number` values for exactly this reason, so a re-import could update the
wrong receipt.

`shipstation_order_id` cannot be the key either: on older rows it holds the
ShipStation orderId, on newer ones the marketplace order number. It is left
untouched here and treated as a display-only field from now on.

This migration adds two nullable columns:

  source            'shipstation' | 'shippo' | 'shopify' | 'manual' | NULL
  external_order_id that platform's own order identifier

Backfill is deliberately conservative. Only rows that unambiguously came from
the Add Sale modal (order_number == id) are stamped 'manual'; everything else
is left NULL and keeps matching on `order_number` through the legacy fallback in
`find_existing_sale`, which stamps each row the first time it is re-imported.

Usage: python migrations/add_receipt_source.py [path-to-db]
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
    columns = [row[1] for row in conn.execute("PRAGMA table_info(sales_receipt)")]
    if not columns:
        raise SystemExit(f"No 'sales_receipt' table in {db_path}")

    added = []
    if 'source' not in columns:
        conn.execute("ALTER TABLE sales_receipt ADD COLUMN source VARCHAR(20)")
        added.append('source')
    if 'external_order_id' not in columns:
        conn.execute("ALTER TABLE sales_receipt ADD COLUMN external_order_id VARCHAR(64)")
        added.append('external_order_id')

    conn.execute("CREATE INDEX IF NOT EXISTS ix_sales_receipt_source "
                 "ON sales_receipt (source)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_sales_receipt_external_order_id "
                 "ON sales_receipt (external_order_id)")

    # The receipt-number column was renamed by
    # migrations/rename_order_identifier_columns.py; work with either name.
    receipt_col = 'receipt_number' if 'receipt_number' in columns else 'order_number'

    if added:
        # Sales created in the Add Sale modal set the receipt number to their own
        # id. Nothing else in the schema produces that pattern.
        cursor = conn.execute(
            f"UPDATE sales_receipt SET source = 'manual' "
            f"WHERE source IS NULL AND {receipt_col} = CAST(id AS TEXT)")
        conn.commit()
        print(f"{db_path}: added {', '.join(added)}; "
              f"stamped {cursor.rowcount} manually-entered sales as source='manual'")
    else:
        conn.commit()
        print(f"{db_path}: source/external_order_id already exist, indexes ensured")

    remaining = conn.execute(
        "SELECT COUNT(*) FROM sales_receipt WHERE source IS NULL").fetchone()[0]
    print(f"{db_path}: {remaining} rows left unstamped (legacy order_number matching applies)")
finally:
    conn.close()
