"""Add the richer product columns and the product_attachment table.

Product gains fields the catalogue had no room for:

  cost        what we pay, for margin. Separate from `price`, which is what the
              customer pays and the only figure the reports use.
  weight_oz   shipping weight in ounces, the unit carrier rate tables use
  category    grouping for the products grid
  vendor      who it is bought from
  notes       free text: build notes, substitutions, anything without a column

product_attachment holds files that belong to a product — datasheets meant to be
printed and shipped with the order:

  stored_name        generated name on disk (never the operator's filename)
  original_name      what it was called when uploaded, used for display
  content_type       browser-reported MIME type
  size_bytes         for display
  uploaded_at        when
  print_with_receipt offer it on the print page of any receipt using this product

The bytes live in instance/product_attachments/, reachable only through a
login-required route. This migration does not touch that directory; the app
creates it on first upload.

Usage: python migrations/add_product_details_and_attachments.py [path-to-db]
Defaults to instance/sales.db. Safe to run more than once.
"""
import os
import sqlite3
import sys

db_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'instance', 'sales.db')

if not os.path.exists(db_path):
    raise SystemExit(f"Database not found: {db_path}")

PRODUCT_COLUMNS = (
    ("cost", "NUMERIC(10, 2) NOT NULL DEFAULT 0"),
    ("weight_oz", "NUMERIC(10, 2) NOT NULL DEFAULT 0"),
    ("category", "VARCHAR(60) NOT NULL DEFAULT ''"),
    ("vendor", "VARCHAR(120) NOT NULL DEFAULT ''"),
    ("notes", "TEXT NOT NULL DEFAULT ''"),
)

conn = sqlite3.connect(db_path)
try:
    existing = [row[1] for row in conn.execute("PRAGMA table_info(product)")]
    if not existing:
        raise SystemExit(f"{db_path}: no product table — is this the right database?")

    for name, ddl in PRODUCT_COLUMNS:
        if name not in existing:
            conn.execute(f"ALTER TABLE product ADD COLUMN {name} {ddl}")
            print(f"{db_path}: added product.{name}")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS product_attachment (
            id INTEGER NOT NULL PRIMARY KEY,
            product_id INTEGER NOT NULL REFERENCES product(id),
            stored_name VARCHAR(120) NOT NULL,
            original_name VARCHAR(255) NOT NULL,
            content_type VARCHAR(100) NOT NULL DEFAULT '',
            size_bytes INTEGER NOT NULL DEFAULT 0,
            uploaded_at DATETIME NOT NULL,
            print_with_receipt BOOLEAN NOT NULL DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS ix_product_attachment_product_id
        ON product_attachment (product_id)
    """)

    conn.commit()
    products = conn.execute("SELECT COUNT(*) FROM product").fetchone()[0]
    files = conn.execute("SELECT COUNT(*) FROM product_attachment").fetchone()[0]
    print(f"{db_path}: product ready ({products} row(s)), "
          f"product_attachment ready ({files} row(s))")
finally:
    conn.close()
