"""Add archived flag to product.

Archived products are hidden from new-sale product dropdowns, and products
that appear on existing sales can only be archived, never deleted (deleting
them would orphan the sale line items that reference them).

Usage: python migrations/add_product_archived.py [path-to-db]
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
    columns = [row[1] for row in conn.execute("PRAGMA table_info(product)")]
    if not columns:
        raise SystemExit(f"No 'product' table in {db_path}")
    if 'archived' in columns:
        print(f"{db_path}: archived already exists, nothing to do")
    else:
        conn.execute("ALTER TABLE product ADD COLUMN archived BOOLEAN NOT NULL DEFAULT 0")
        conn.commit()
        print(f"{db_path}: added archived (all products start unarchived)")
finally:
    conn.close()
