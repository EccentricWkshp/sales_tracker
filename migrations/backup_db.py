"""Snapshot the database without starting the app.

The app takes a backup on every start; this script covers installs that stay up
for weeks at a time. Point Windows Task Scheduler at "Backup Sales Tracker.bat",
or run it directly:

    python migrations/backup_db.py [path-to-db] [--retain N]

Uses sqlite3's online backup API, so it is safe to run while the app is serving —
unlike copying the file, which can capture a torn write. Verifies the result with
PRAGMA quick_check and reports orphaned rows, then prunes all but the newest
`retain` snapshots (default 14, or SALES_TRACKER_BACKUP_RETAIN).
"""
import argparse
import os
import sqlite3
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('db_path', nargs='?',
                    default=os.path.join(BASE_DIR, 'instance', 'sales.db'))
parser.add_argument('--retain', type=int,
                    default=int(os.environ.get('SALES_TRACKER_BACKUP_RETAIN', '14')))
parser.add_argument('--backup-dir',
                    default=os.path.join(BASE_DIR, 'instance', 'backups'))
args = parser.parse_args()

if not os.path.exists(args.db_path):
    raise SystemExit(f"Database not found: {args.db_path}")

os.makedirs(args.backup_dir, exist_ok=True)
stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
target = os.path.join(args.backup_dir, f'sales-{stamp}.db')

source = sqlite3.connect(args.db_path)
try:
    destination = sqlite3.connect(target)
    try:
        source.backup(destination)
    finally:
        destination.close()

    integrity = source.execute('PRAGMA quick_check').fetchone()[0]
    orphans = source.execute('PRAGMA foreign_key_check').fetchall()
finally:
    source.close()

print(f"Backup written to {target}")
print(f"quick_check: {integrity}")
if integrity != 'ok':
    print("WARNING: the source database failed its integrity check.", file=sys.stderr)

if orphans:
    print(f"WARNING: {len(orphans)} orphaned row(s) violate foreign keys:", file=sys.stderr)
    for table, rowid, parent, _ in orphans[:20]:
        print(f"  {table} rowid={rowid} -> missing {parent}", file=sys.stderr)
else:
    print("foreign_key_check: ok")

snapshots = sorted(f for f in os.listdir(args.backup_dir)
                   if f.startswith('sales-') and f.endswith('.db'))
if args.retain > 0:
    for stale in snapshots[:-args.retain]:
        os.remove(os.path.join(args.backup_dir, stale))
        print(f"Pruned old backup {stale}")

print(f"{len(os.listdir(args.backup_dir))} snapshot(s) retained in {args.backup_dir}")
