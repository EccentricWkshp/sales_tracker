"""Add is_manufactured to product and backfill from the legacy SKU convention.

Products whose SKU ends in a capital 'A' were previously counted as
manufacturing revenue on the state taxes report. This adds an explicit
boolean column (editable on the products page) and seeds it to match,
so report figures are unchanged until a product is deliberately edited.

Usage: python migrations/add_product_is_manufactured.py [path-to-db]
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
    if 'is_manufactured' in columns:
        print(f"{db_path}: is_manufactured already exists, nothing to do")
    else:
        conn.execute("ALTER TABLE product ADD COLUMN is_manufactured BOOLEAN NOT NULL DEFAULT 0")
        # GLOB is case-sensitive, matching the old Python sku.endswith('A') exactly
        conn.execute("UPDATE product SET is_manufactured = 1 WHERE sku GLOB '*A'")
        conn.commit()
        flagged = conn.execute("SELECT COUNT(*) FROM product WHERE is_manufactured = 1").fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM product").fetchone()[0]
        print(f"{db_path}: added is_manufactured; flagged {flagged} of {total} products")
finally:
    conn.close()
