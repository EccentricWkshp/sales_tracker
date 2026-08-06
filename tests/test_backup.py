"""Database backups (roadmap B1).

``backup_database`` runs on every start and from a Task Scheduler job. It uses
``sqlite3.Connection.backup()`` rather than a file copy so it is safe to call
while the app is serving.
"""
import os
import time

import pytest


def _snapshots(directory):
    return sorted(f for f in os.listdir(directory)
                  if f.startswith('sales-') and f.endswith('.db'))


def test_a_backup_is_written(A, ctx, tmp_path):
    target = A.backup_database(db_path=A.configured_sqlite_path(),
                               backup_dir=str(tmp_path), retain=5)
    assert target and os.path.exists(target)
    assert os.path.basename(target).startswith('sales-')


def test_the_snapshot_is_a_readable_database(A, ctx, tmp_path):
    """A file copy of a live WAL database can be torn; the backup API cannot."""
    import sqlite3

    target = A.backup_database(db_path=A.configured_sqlite_path(),
                               backup_dir=str(tmp_path), retain=5)
    connection = sqlite3.connect(target)
    try:
        assert connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        # And it carries the data, not just the schema
        assert connection.execute('SELECT COUNT(*) FROM product').fetchone()[0] == 3
    finally:
        connection.close()


def test_retention_prunes_the_oldest(A, ctx, tmp_path):
    """Names are timestamped to the second, so the writes have to be spaced."""
    for _ in range(4):
        A.backup_database(db_path=A.configured_sqlite_path(),
                          backup_dir=str(tmp_path), retain=2)
        time.sleep(1.05)

    kept = _snapshots(str(tmp_path))
    assert len(kept) == 2


def test_retention_keeps_the_newest(A, ctx, tmp_path):
    written = []
    for _ in range(3):
        written.append(os.path.basename(
            A.backup_database(db_path=A.configured_sqlite_path(),
                              backup_dir=str(tmp_path), retain=2)))
        time.sleep(1.05)

    assert _snapshots(str(tmp_path)) == sorted(written[-2:])


def test_retain_zero_keeps_everything(A, ctx, tmp_path):
    """`snapshots[:-0]` would slice the whole list, deleting every backup."""
    A.backup_database(db_path=A.configured_sqlite_path(),
                      backup_dir=str(tmp_path), retain=0)
    time.sleep(1.05)
    A.backup_database(db_path=A.configured_sqlite_path(),
                      backup_dir=str(tmp_path), retain=0)
    assert len(_snapshots(str(tmp_path))) == 2


def test_a_missing_database_is_reported_not_crashed(A, ctx, tmp_path):
    assert A.backup_database(db_path=str(tmp_path / 'nothing-here.db'),
                             backup_dir=str(tmp_path), retain=2) is None


def test_the_backup_directory_is_created_on_demand(A, ctx, tmp_path):
    destination = tmp_path / 'not' / 'yet' / 'there'
    target = A.backup_database(db_path=A.configured_sqlite_path(),
                               backup_dir=str(destination), retain=2)
    assert target and os.path.exists(target)


def test_backup_follows_the_configured_database_not_the_default(A, ctx):
    """The override exists so a second install — or this test suite — gets its
    own database backed up rather than instance/sales.db."""
    assert A.configured_sqlite_path().replace('\\', '/').endswith('/test.db')


def test_the_cli_command_is_registered(A):
    assert 'backup-db' in A.app.cli.commands
    assert 'create-admin' in A.app.cli.commands
