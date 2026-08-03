"""Remove placeholder customer records that no longer belong to any sale.

Imports mint a `placeholder_<uuid>@example.com` customer when an order arrives
with no email. Two situations leave those behind with nothing attached:

  * the sale they were created for was deleted
  * an older build of the importer created one per re-fetch

Orders whose buyer details the platform withholds no longer produce these at all
— they go to the pending-order queue instead (see add_pending_orders.py).

Only customers matching ALL of the following are removed:
  * email begins with 'placeholder_'
  * no sales receipts reference them
  * no ShipStation customer mapping references them

Runs as a dry run by default. Pass --apply to delete.

Usage: python migrations/cleanup_placeholder_customers.py [path-to-db] [--apply]
"""
import argparse
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('db_path', nargs='?',
                    default=os.path.join(BASE_DIR, 'instance', 'sales.db'))
parser.add_argument('--apply', action='store_true',
                    help='actually delete (default is a dry run)')
args = parser.parse_args()

if not os.path.exists(args.db_path):
    raise SystemExit(f"Database not found: {args.db_path}")

ORPHANS = """
    SELECT c.id, c.name, c.email
    FROM customer c
    WHERE c.email LIKE 'placeholder\\_%' ESCAPE '\\'
      AND NOT EXISTS (SELECT 1 FROM sales_receipt s WHERE s.customer_id = c.id)
      AND NOT EXISTS (SELECT 1 FROM ship_station_customer_mapping m WHERE m.customer_id = c.id)
"""

conn = sqlite3.connect(args.db_path)
try:
    orphans = conn.execute(ORPHANS).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) FROM customer WHERE email LIKE 'placeholder\\_%' ESCAPE '\\'"
    ).fetchone()[0]

    print(f"{args.db_path}: {total} placeholder customer(s), {len(orphans)} with no sales")
    for cid, name, email in orphans[:40]:
        print(f"  {cid}: {name!r} <{email}>")
    if len(orphans) > 40:
        print(f"  ...and {len(orphans) - 40} more")

    if not orphans:
        print("Nothing to clean up.")
    elif not args.apply:
        print("\nDry run — pass --apply to delete these.")
    else:
        conn.execute(f"DELETE FROM customer WHERE id IN (SELECT id FROM ({ORPHANS}))")
        conn.commit()
        print(f"\nDeleted {len(orphans)} orphaned placeholder customer(s)")
finally:
    conn.close()
