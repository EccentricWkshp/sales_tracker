"""Repoint imported receipt numbers at the receipt's own id.

Three identifiers had drifted into each other on imported sales:

  order_number          Sales Tracker's own receipt number — a unique identifier
                        within this app. `add_sale` sets it to the receipt's id.
  shipstation_order_id  the marketplace/platform order number, shown as "Order #".
  external_order_id     the platform's internal order id, the re-import match key.

The importers were writing the marketplace order number into `order_number`, so
the Receipt # column showed the same value as Order # instead of a Sales Tracker
identifier. This fixes the rows that landed that way.

Deliberately narrow:

  * Only rows with a non-null `source` other than 'manual' — i.e. rows written by
    the current importers. Rows from before the `source` column existed are left
    alone: their `order_number` is still the fallback key `find_existing_sale`
    uses to recognise them on re-import, and rewriting it would orphan them.
  * 'manual' rows already satisfy order_number == id.
  * If `shipstation_order_id` is empty, the marketplace order number is copied
    into it first so the Order # column keeps showing it.

Run with --dry-run first to see what would change.

Usage: python migrations/fix_imported_receipt_numbers.py [path-to-db] [--dry-run]
Defaults to instance/sales.db. Safe to run more than once.
"""
import argparse
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('db_path', nargs='?',
                    default=os.path.join(BASE_DIR, 'instance', 'sales.db'))
parser.add_argument('--dry-run', action='store_true',
                    help='report what would change without writing')
args = parser.parse_args()

if not os.path.exists(args.db_path):
    raise SystemExit(f"Database not found: {args.db_path}")

conn = sqlite3.connect(args.db_path)
try:
    columns = [row[1] for row in conn.execute("PRAGMA table_info(sales_receipt)")]
    if 'source' not in columns:
        raise SystemExit("Run migrations/add_receipt_source.py first.")

    # These columns were renamed by rename_order_identifier_columns.py; this
    # script must work either side of that migration.
    receipt_col = 'receipt_number' if 'receipt_number' in columns else 'order_number'
    external_col = ('external_order_number' if 'external_order_number' in columns
                    else 'shipstation_order_id')

    # NULL-safe: a receipt with no number at all also needs one
    WRONG_RECEIPT_NUMBER = f"""
        source IS NOT NULL
        AND source != 'manual'
        AND ({receipt_col} IS NULL OR {receipt_col} != CAST(id AS TEXT))
    """

    affected = conn.execute(f"""
        SELECT id, {receipt_col}, {external_col}, source
        FROM sales_receipt
        WHERE {WRONG_RECEIPT_NUMBER}
    """).fetchall()

    if not affected:
        print(f"{args.db_path}: nothing to fix — every imported receipt number "
              f"already matches its id")
    else:
        print(f"{args.db_path}: {len(affected)} imported sale(s) to correct")
        for sid, order_number, ss_order_id, source in affected:
            keeps = ss_order_id or order_number
            print(f"  sale {sid} ({source}): Receipt # {order_number!r} -> {str(sid)!r}, "
                  f"Order # stays {keeps!r}")

        if args.dry_run:
            print("\n--dry-run: no changes written")
        else:
            # Preserve the marketplace number in the Order # column if it is empty
            conn.execute(f"""
                UPDATE sales_receipt
                SET {external_col} = {receipt_col}
                WHERE {WRONG_RECEIPT_NUMBER}
                  AND ({external_col} IS NULL OR {external_col} = '')
            """)
            cursor = conn.execute(f"""
                UPDATE sales_receipt
                SET {receipt_col} = CAST(id AS TEXT)
                WHERE {WRONG_RECEIPT_NUMBER}
            """)
            conn.commit()
            print(f"\nUpdated {cursor.rowcount} receipt number(s)")
finally:
    conn.close()
