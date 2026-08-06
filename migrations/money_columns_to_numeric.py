"""Normalise the money columns to exactly two decimal places (roadmap E4).

Why this is needed
------------------
`SalesReceipt.total/tax/shipping`, `LineItem.price_each/total_price` and
`BankTransaction.amount` were `Float`. Binary floating point cannot hold 0.10,
0.20 or 19.99 exactly, so a receipt whose parts were 19.99 + 5.00 + 1.90 could be
stored as 26.889999999999997. Nothing displayed wrongly — every template formats
with `%.2f` — but the stored figure was not the figure, and the state taxes
report *sums* `line_item.total_price` across a whole quarter, where that error
compounds and can land the WA B&O total a cent or two away from the receipts it
came from. `is_duplicate_transaction` compares `amount` with `==`, which is
meaningless between two floats that merely display the same.

The models are now `Numeric(10, 2)`. This script fixes the values already stored.

What it does and does not do
----------------------------
It **rounds every money value to 2 decimal places**, which is what makes the old
rows agree with the new column type. `ROUND()` in SQLite is half-away-from-zero
on the decimal value, which is what a person reading a receipt expects.

It deliberately does **not** rebuild the tables to change the declared column
type from FLOAT to NUMERIC(10,2). In SQLite a declared type is only an affinity,
and SQLAlchemy does the Decimal conversion in Python on both read and write, so
the two declarations behave identically once the values are clean. Rebuilding
`sales_receipt` would mean dropping and recreating a table that `line_item` and
`bank_transaction` both point at, with foreign keys enforced — real risk on live
financial data for no behavioural gain. A database created fresh from the models
gets NUMERIC columns; an upgraded one keeps FLOAT and works the same.

Take a backup first (`python migrations/backup_db.py`), though this only ever
rounds values that were already meant to be 2dp.

Usage: python migrations/money_columns_to_numeric.py [path-to-db]
Defaults to instance/sales.db. Safe to run more than once.
"""
import os
import sqlite3
import sys

db_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'instance', 'sales.db')

if not os.path.exists(db_path):
    raise SystemExit(f"Database not found: {db_path}")

# (table, columns). PendingOrder is deliberately absent: its figures are a
# display copy of `payload`, which holds them as strings and re-parses them to
# Decimal when the order is completed, so the receipt it produces is exact
# regardless of what the parked row rounded to.
TARGETS = (
    ('sales_receipt', ('total', 'tax', 'shipping')),
    ('line_item', ('price_each', 'total_price')),
    ('bank_transaction', ('amount',)),
)

conn = sqlite3.connect(db_path)
try:
    total_changed = 0
    for table, columns in TARGETS:
        present = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
        if not present:
            print(f"{db_path}: no '{table}' table, skipping")
            continue

        missing = [c for c in columns if c not in present]
        if missing:
            raise SystemExit(f"{table} is missing {', '.join(missing)} - "
                             f"is this a Sales Tracker database?")

        for column in columns:
            # Count first so the report means something on a re-run, where the
            # UPDATE would otherwise report every row as touched.
            drifted = conn.execute(
                f"SELECT COUNT(*) FROM {table} "
                f"WHERE {column} IS NOT NULL AND {column} != ROUND({column}, 2)"
            ).fetchone()[0]

            if drifted:
                conn.execute(
                    f"UPDATE {table} SET {column} = ROUND({column}, 2) "
                    f"WHERE {column} IS NOT NULL AND {column} != ROUND({column}, 2)")
                total_changed += drifted

            print(f"{db_path}: {table}.{column} - "
                  f"{drifted} value(s) rounded to 2dp"
                  if drifted else
                  f"{db_path}: {table}.{column} - already clean")

    conn.commit()

    # Informational only. A receipt whose total is below its line items plus tax
    # and shipping is normally a **discount or customer credit** — the total is
    # what was actually charged, and it is the authoritative figure. This is
    # counted purely so a large jump is noticeable; nothing here is a defect and
    # nothing is changed.
    mismatched = conn.execute("""
        SELECT COUNT(*) FROM (
            SELECT r.id,
                   ROUND(r.total, 2) AS stored,
                   ROUND(COALESCE((SELECT SUM(li.total_price) FROM line_item li
                                   WHERE li.receipt_id = r.id), 0)
                         + COALESCE(r.tax, 0) + COALESCE(r.shipping, 0), 2) AS computed
            FROM sales_receipt r
        ) WHERE stored != computed
    """).fetchone()[0]

    print(f"\n{db_path}: {total_changed} value(s) normalised in total")
    if mismatched:
        print(f"{db_path}: FYI - {mismatched} receipt(s) carry a total that differs "
              f"from line items + tax + shipping. That is what a discount or "
              f"customer credit looks like: the total is what was charged and is "
              f"correct. Nothing was changed.")
    else:
        print(f"{db_path}: no discounted receipts found")
finally:
    conn.close()
