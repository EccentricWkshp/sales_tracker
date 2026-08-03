"""Rename the order-identifier columns to say what they actually hold.

The old names date from when ShipStation was the only import route, and became
actively misleading once Shippo and Shopify wrote to the same columns — a Shopify
order number was being stored in a field called `shipstation_order_id`.

    sales_receipt.order_number         -> receipt_number
    sales_receipt.shipstation_order_id -> external_order_number
    pending_order.order_number         -> external_order_number

Leaving the meanings explicit, a sale now carries three identifiers:

    receipt_number        Sales Tracker's own receipt number — always the
                          receipt's id. Unique within this app.
    external_order_number the selling platform's human-facing order number
                          ("#1001", "4094194072"). Display only.
    external_order_id     the platform's internal order id. The key that matches
                          a re-imported order back to its receipt. Not displayed.

Requires SQLite 3.25+ for ALTER TABLE ... RENAME COLUMN (2018; anything shipping
with a supported Python has it).

Run against a stopped app, after taking a backup. Reversing it is the same
statements with the names swapped.

Usage: python migrations/rename_order_identifier_columns.py [path-to-db] [--dry-run]
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

if tuple(map(int, sqlite3.sqlite_version.split('.'))) < (3, 25, 0):
    raise SystemExit(f"SQLite {sqlite3.sqlite_version} is too old for RENAME COLUMN "
                     f"(needs 3.25+)")

# (table, old column, new column)
RENAMES = (
    ('sales_receipt', 'order_number', 'receipt_number'),
    ('sales_receipt', 'shipstation_order_id', 'external_order_number'),
    ('pending_order', 'order_number', 'external_order_number'),
)

conn = sqlite3.connect(args.db_path)
try:
    planned, skipped = [], []
    for table, old, new in RENAMES:
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info({table})')]
        if not columns:
            skipped.append(f'{table}: table not present')
            continue
        if new in columns and old not in columns:
            skipped.append(f'{table}.{new}: already renamed')
            continue
        if new in columns and old in columns:
            skipped.append(f'{table}: both {old} and {new} exist — resolve by hand')
            continue
        if old not in columns:
            skipped.append(f'{table}.{old}: column not present')
            continue
        planned.append((table, old, new))

    for note in skipped:
        print(f"  skip  {note}")

    if not planned:
        print(f"{args.db_path}: nothing to rename")
    else:
        for table, old, new in planned:
            print(f"  rename {table}.{old} -> {new}")

        if args.dry_run:
            print("\n--dry-run: no changes written")
        else:
            for table, old, new in planned:
                conn.execute(f'ALTER TABLE {table} RENAME COLUMN "{old}" TO "{new}"')
            conn.commit()
            print(f"\n{args.db_path}: renamed {len(planned)} column(s)")

            integrity = conn.execute('PRAGMA quick_check').fetchone()[0]
            print(f"quick_check: {integrity}")
finally:
    conn.close()
