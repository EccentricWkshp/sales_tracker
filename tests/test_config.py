"""App configuration, SQLite pragmas and the test harness's own safety rails.

The first two tests are the ones that matter most: if the suite is pointed at
live data or inherits the developer's real API credentials, every other result
in this directory is worthless.
"""
import os

from sqlalchemy import text


def test_bound_to_the_scratch_database(A):
    """Never instance/sales.db."""
    path = (A.configured_sqlite_path() or '').replace('\\', '/').lower()
    assert path.endswith('/test.db')
    assert 'instance/sales.db' not in path


def test_no_real_integration_credentials_are_visible(A):
    """No environment variable the registry reads may carry a value.

    ``.env`` in this repo holds live Shopify and Etsy secrets and ``app.py``
    loads it on import. conftest strips them; this is the assertion that the
    stripping still covers every registered platform.
    """
    leaked = []
    for spec in A.INTEGRATIONS.values():
        for field in spec.env_fields:
            if spec.env_value(field):
                leaked.append(f'{spec.key}.{field}')
    for field in A.SHOPIFY_ENV_FIELDS:
        if A.shopify_env_value(field):
            leaked.append(f'shopify.{field}')
    assert leaked == [], f'live credentials reachable from the environment: {leaked}'


def test_every_integration_starts_disabled(A, ctx):
    """A fresh database enables nothing, so no test can make an outbound call."""
    assert [spec.key for spec in A.integration_specs() if spec.is_enabled()] == []


def test_foreign_keys_are_enforced(A, ctx):
    """SQLite defaults this OFF, which let the old import pipeline orphan rows."""
    with A.db.engine.connect() as conn:
        assert conn.execute(text('PRAGMA foreign_keys')).scalar() == 1


def test_journal_mode_is_wal(A, ctx):
    with A.db.engine.connect() as conn:
        assert conn.execute(text('PRAGMA journal_mode')).scalar() == 'wal'


def test_busy_timeout_is_set(A, ctx):
    with A.db.engine.connect() as conn:
        assert conn.execute(text('PRAGMA busy_timeout')).scalar() == 20000


def test_session_cookie_hardening(A):
    assert A.app.config['SESSION_COOKIE_HTTPONLY'] is True
    assert A.app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
    assert A.app.config['PERMANENT_SESSION_LIFETIME'].days == 14


def test_secure_cookie_is_opt_in(A):
    """The app is served over plain HTTP on the LAN; Secure would break login."""
    assert A.app.config['SESSION_COOKIE_SECURE'] is False


def test_upload_size_is_capped(A):
    assert A.app.config['MAX_CONTENT_LENGTH'] == 16 * 1024 * 1024


def test_secret_key_is_set(A):
    assert A.app.config['SECRET_KEY']


def test_session_protection_is_basic(A):
    """'strong' drops the session when the client IP changes, which on a LAN
    logs out a laptop that roams between access points."""
    assert A.login_manager.session_protection == 'basic'
