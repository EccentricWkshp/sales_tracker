"""Create the etsy_credentials and ebay_credentials tables.

Both marketplaces need OAuth 2.0 seller consent rather than a bare API key, so
each row stores the app's identity plus the tokens the consent round trip
produces:

  -- identity, entered on the Management page (or via .env) --
  client_id       Etsy: the app keystring.  eBay: the App ID (Client ID)
  client_secret   Etsy: the shared secret.  eBay: the Cert ID
  shop_id         Etsy only — numeric shop id; discovered automatically
  ru_name         eBay only — the RuName alias eBay sends instead of a URL
  sandbox         eBay only — use the sandbox hosts instead of production

  -- produced by the consent flow, never entered by hand --
  access_token             short-lived bearer token
  refresh_token            long-lived; renews the above without re-consent
  access_token_expires_at  when the bearer token lapses
  refresh_token_expires_at eBay's refresh tokens expire (~18 months); Etsy's do not
  oauth_state              one-shot CSRF nonce, held only across the redirect
  oauth_verifier           PKCE verifier (Etsy); held only across the redirect

  enabled         show the card on the dashboard and allow fetches

Tokens are TEXT because eBay user tokens run to several thousand characters.

Usage: python migrations/add_marketplace_credentials.py [path-to-db]
Defaults to instance/sales.db. Safe to run more than once.
"""
import os
import sqlite3
import sys

db_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'instance', 'sales.db')

if not os.path.exists(db_path):
    raise SystemExit(f"Database not found: {db_path}")

# Columns every OAuth marketplace shares
OAUTH_COLUMNS = (
    ("access_token", "TEXT NOT NULL DEFAULT ''"),
    ("refresh_token", "TEXT NOT NULL DEFAULT ''"),
    ("access_token_expires_at", "DATETIME"),
    ("refresh_token_expires_at", "DATETIME"),
    ("oauth_state", "VARCHAR(64) NOT NULL DEFAULT ''"),
    ("oauth_verifier", "VARCHAR(128) NOT NULL DEFAULT ''"),
)

TABLES = {
    'etsy_credentials': (
        ("client_id", "VARCHAR(120) NOT NULL DEFAULT ''"),
        ("client_secret", "VARCHAR(120) NOT NULL DEFAULT ''"),
        ("shop_id", "VARCHAR(50) NOT NULL DEFAULT ''"),
    ) + OAUTH_COLUMNS + (
        ("enabled", "BOOLEAN NOT NULL DEFAULT 0"),
    ),
    'ebay_credentials': (
        ("client_id", "VARCHAR(120) NOT NULL DEFAULT ''"),
        ("client_secret", "VARCHAR(120) NOT NULL DEFAULT ''"),
        ("ru_name", "VARCHAR(200) NOT NULL DEFAULT ''"),
        ("sandbox", "BOOLEAN NOT NULL DEFAULT 0"),
    ) + OAUTH_COLUMNS + (
        ("enabled", "BOOLEAN NOT NULL DEFAULT 0"),
    ),
}

conn = sqlite3.connect(db_path)
try:
    for table, columns in TABLES.items():
        body = ",\n            ".join(f"{name} {ddl}" for name, ddl in columns)
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
            id INTEGER NOT NULL PRIMARY KEY,
            {body}
            )
        """)

        # Tolerate a table created by an earlier revision that lacked a column
        existing = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
        for name, ddl in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                print(f"{db_path}: added {table}.{name}")

        rows = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"{db_path}: {table} ready ({rows} row(s))")

    conn.commit()
finally:
    conn.close()
