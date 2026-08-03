"""Create the shopify_credentials table used by the Shopify integration.

Stores one row for a single Shopify store, supporting both authentication
routes Shopify now offers:

  shop_domain      the *.myshopify.com host (not the customer-facing domain)
  auth_mode        'token' (legacy custom app) or 'client_credentials'
                   (Dev Dashboard app)

  -- auth_mode='token' --
  api_key          Admin API access token (shpat_...), sent as X-Shopify-Access-Token
  api_secret       the custom app's API secret key, verifies webhook HMACs

  -- auth_mode='client_credentials' --
  client_id        Dev Dashboard client ID
  client_secret    Dev Dashboard client secret; also verifies webhook HMACs
  access_token     cached token from the client-credentials exchange
  access_token_expires_at
                   when that cached token expires (Shopify issues ~24 hours)

  enabled          show the Shopify card on the dashboard and allow fetches
  webhooks_enabled accept inbound POSTs on /shopify/webhook

Usage: python migrations/add_shopify_credentials.py [path-to-db]
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
        CREATE TABLE IF NOT EXISTS shopify_credentials (
            id INTEGER NOT NULL PRIMARY KEY,
            shop_domain VARCHAR(120) NOT NULL DEFAULT '',
            auth_mode VARCHAR(20) NOT NULL DEFAULT 'token',
            api_key VARCHAR(120) NOT NULL,
            api_secret VARCHAR(120) NOT NULL DEFAULT '',
            client_id VARCHAR(120) NOT NULL DEFAULT '',
            client_secret VARCHAR(120) NOT NULL DEFAULT '',
            access_token VARCHAR(255) NOT NULL DEFAULT '',
            access_token_expires_at DATETIME,
            enabled BOOLEAN NOT NULL DEFAULT 0,
            webhooks_enabled BOOLEAN NOT NULL DEFAULT 0
        )
    """)

    # Tolerate a table created by an earlier revision that lacked these columns
    columns = [row[1] for row in conn.execute("PRAGMA table_info(shopify_credentials)")]
    for name, ddl in (
        ('shop_domain', "ALTER TABLE shopify_credentials ADD COLUMN shop_domain VARCHAR(120) NOT NULL DEFAULT ''"),
        ('auth_mode', "ALTER TABLE shopify_credentials ADD COLUMN auth_mode VARCHAR(20) NOT NULL DEFAULT 'token'"),
        ('api_secret', "ALTER TABLE shopify_credentials ADD COLUMN api_secret VARCHAR(120) NOT NULL DEFAULT ''"),
        ('client_id', "ALTER TABLE shopify_credentials ADD COLUMN client_id VARCHAR(120) NOT NULL DEFAULT ''"),
        ('client_secret', "ALTER TABLE shopify_credentials ADD COLUMN client_secret VARCHAR(120) NOT NULL DEFAULT ''"),
        ('access_token', "ALTER TABLE shopify_credentials ADD COLUMN access_token VARCHAR(255) NOT NULL DEFAULT ''"),
        ('access_token_expires_at', "ALTER TABLE shopify_credentials ADD COLUMN access_token_expires_at DATETIME"),
        ('webhooks_enabled', "ALTER TABLE shopify_credentials ADD COLUMN webhooks_enabled BOOLEAN NOT NULL DEFAULT 0"),
    ):
        if name not in columns:
            conn.execute(ddl)
            print(f"{db_path}: added shopify_credentials.{name}")

    conn.commit()
    rows = conn.execute("SELECT COUNT(*) FROM shopify_credentials").fetchone()[0]
    print(f"{db_path}: shopify_credentials ready ({rows} row(s))")
finally:
    conn.close()
