"""Shared fixtures for the Sales Tracker test suite.

Two things have to happen before ``import app``, and both are why this file
reads the way it does:

1. **Bind a scratch database.** ``app.py`` builds the Flask app and the
   SQLAlchemy engine at import time from ``SALES_TRACKER_DATABASE_URI``.
   Assigning ``app.config[...]`` afterwards does not rebind the engine, so the
   override has to be in ``os.environ`` first. That variable exists for exactly
   this purpose. Tests must never touch ``instance/sales.db``.

2. **Neutralise the real credentials.** ``app.py`` calls ``load_dotenv`` on
   import, and the developer ``.env`` in this repo holds live Shopify and Etsy
   secrets. An earlier ad-hoc run of this battery inherited them and made a real
   Shopify API call. ``load_dotenv(override=False)`` skips any key already
   present in the environment — presence, not truthiness — so setting them to
   ``''`` here blocks the file. After import they are removed outright, driven by
   the integration registry so a newly registered variable cannot slip past.
   ``test_config.py`` asserts the result.
"""
import os
import pathlib
import shutil
import sys
import tempfile

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# --------------------------------------------------------------------------
# Environment, before app is imported
# --------------------------------------------------------------------------

_TMP_ROOT = tempfile.mkdtemp(prefix='sales-tracker-tests-')
_DB_PATH = os.path.join(_TMP_ROOT, 'test.db')

os.environ['SALES_TRACKER_DATABASE_URI'] = (
    'sqlite:///' + _DB_PATH.replace('\\', '/') + '?timeout=20')
# Small enough that the retention test can prove pruning happens
os.environ['SALES_TRACKER_BACKUP_RETAIN'] = '2'
# Supply a key so load_secret_key() does not write into the real instance/
os.environ['FLASK_SECRET_KEY'] = 'sales-tracker-test-secret-key'
os.environ['SESSION_COOKIE_SECURE'] = ''

# Blocks the .env file. The post-import sweep below is the authoritative one;
# this list only has to cover what a .env might carry.
_ENV_BLOCKLIST = (
    'SHOPIFY_ADMIN_API_TOKEN', 'SHOPIFY_ACCESS_TOKEN', 'SHOPIFY_API_KEY',
    'SHOPIFY_API_SECRET', 'SHOPIFY_CLIENT_ID', 'SHOPIFY_CLIENT_SECRET',
    'SHOPIFY_SECRET', 'SHOPIFY_SHOP_DOMAIN', 'SHOPIFY_STORE_DOMAIN',
    'ETSY_KEYSTRING', 'ETSY_SHAREDSECRET', 'ETSY_CLIENT_ID',
    'ETSY_CLIENT_SECRET', 'ETSY_SHOP_ID',
    'EBAY_APP_ID', 'EBAY_CERT_ID', 'EBAY_CLIENT_ID', 'EBAY_CLIENT_SECRET',
    'EBAY_RU_NAME',
)
for _name in _ENV_BLOCKLIST:
    os.environ[_name] = ''

import app as _app_module  # noqa: E402


def _scrub_integration_env():
    """Remove every environment variable the registry would read as a credential.

    Registry-driven rather than a hand-kept list: adding an env override to a new
    integration should not silently reopen the hole this closes.
    """
    for spec in _app_module.INTEGRATIONS.values():
        for names in spec.env_fields.values():
            for name in names:
                os.environ.pop(name, None)
    for names in _app_module.SHOPIFY_ENV_FIELDS.values():
        for name in names:
            os.environ.pop(name, None)
    for name in _ENV_BLOCKLIST:
        os.environ.pop(name, None)


_scrub_integration_env()

# The bound database must be the scratch file, never the live one. If this
# assertion ever fires, stop — the next line would create tables in real data.
_bound = (_app_module.configured_sqlite_path() or '').replace('\\', '/').lower()
assert _bound == _DB_PATH.replace('\\', '/').lower(), (
    f'Tests are bound to {_bound!r}, not the scratch database. Refusing to run.')


def pytest_sessionfinish(session, exitstatus):
    # Flask-SQLAlchemy scopes the session to the app context, so both calls need
    # one; without it teardown raises "Working outside of application context".
    with _app_module.app.app_context():
        _app_module.db.session.remove()
        _app_module.db.engine.dispose()
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)


# --------------------------------------------------------------------------
# Core fixtures
# --------------------------------------------------------------------------

@pytest.fixture(scope='session')
def A():
    """The imported ``app`` module. Named for how the ad-hoc scripts used it."""
    return _app_module


TEST_USERNAME = 'test-operator'
TEST_PASSWORD = 'test-password'


@pytest.fixture(autouse=True)
def fresh_db(A, tmp_path, monkeypatch):
    """A schema built from the models, reseeded for every test.

    Rebuilding beats wrapping each test in a rollback: the routes commit, and
    ``import_processed_orders`` opens its own savepoints, so an outer transaction
    would be fighting the code under test.
    """
    # Uploaded bytes go to a per-test directory, never the real instance/
    monkeypatch.setattr(A, 'PRODUCT_ATTACHMENT_DIR', str(tmp_path / 'attachments'))

    with A.app.app_context():
        A.db.session.remove()
        A.db.drop_all()
        A.db.create_all()
        _seed(A)
        A.db.session.commit()
    yield
    with A.app.app_context():
        A.db.session.remove()


def _seed(A):
    """The minimum an install has: an operator, company details, stock, a buyer."""
    user = A.User(username=TEST_USERNAME)
    user.set_password(TEST_PASSWORD)
    A.db.session.add(user)

    A.db.session.add(A.CompanyInfo(
        name='Eccentric Workshop', address='1 Workshop Way\nOlympia, WA 98501',
        phone='360-555-0100', email='sales@example.com', logo=None))

    A.db.session.add_all([
        A.Product(sku='WIDGET-1', description='Standard widget', price=100,
                  cost=40, weight_oz=8, category='Widgets', vendor='Acme',
                  is_manufactured=True),
        A.Product(sku='GADGET-1', description='Standard gadget', price=10,
                  cost=0, weight_oz=2, category='Gadgets', vendor='Acme',
                  is_manufactured=False),
        A.Product(sku='OLD-1', description='Discontinued', price=5,
                  archived=True),
    ])

    A.db.session.add(A.Customer(
        name='Ada Buyer', email='ada@example.com',
        billing_address='2 Buyer Lane\nOlympia, WA 98501',
        shipping_address='2 Buyer Lane\nOlympia, WA 98501',
        phone='360-555-0111'))
    A.db.session.flush()


@pytest.fixture
def anon_client(A):
    """A test client with no session, for checking that routes are gated.

    Its own client, not the one `client` logs in — a test asking for both must
    get one authenticated and one genuinely anonymous.
    """
    return A.app.test_client()


@pytest.fixture
def client(A):
    """A logged-in test client. The seeded operator is always id 1."""
    authenticated = A.app.test_client()
    with authenticated.session_transaction() as session:
        session['_user_id'] = '1'
        session['_fresh'] = True
    return authenticated


@pytest.fixture
def ctx(A):
    """An application context, for calling app internals directly."""
    with A.app.app_context():
        yield


# --------------------------------------------------------------------------
# Handles to the seeded rows. Ids are read inside a context and returned as
# plain ints so tests never hold a detached instance across contexts.
# --------------------------------------------------------------------------

@pytest.fixture
def customer_id(A):
    with A.app.app_context():
        return A.Customer.query.filter_by(email='ada@example.com').one().id


@pytest.fixture
def widget_id(A):
    with A.app.app_context():
        return A.Product.query.filter_by(sku='WIDGET-1').one().id


@pytest.fixture
def gadget_id(A):
    with A.app.app_context():
        return A.Product.query.filter_by(sku='GADGET-1').one().id


# --------------------------------------------------------------------------
# Factories
# --------------------------------------------------------------------------

@pytest.fixture
def make_customer(A):
    def _make(name='Extra Buyer', email=None, **kwargs):
        with A.app.app_context():
            customer = A.Customer(
                name=name,
                email=email or f'{name.lower().replace(" ", "-")}@example.com',
                billing_address=kwargs.pop('billing_address', '9 Other St\nTacoma, WA 98402'),
                shipping_address=kwargs.pop('shipping_address', '9 Other St\nTacoma, WA 98402'),
                **kwargs)
            A.db.session.add(customer)
            A.db.session.commit()
            return customer.id
    return _make


@pytest.fixture
def make_sale(A):
    """A committed receipt with line items, returning its id.

    ``items`` is a list of (product_id, quantity, price_each).
    """
    def _make(customer_id, items, date=None, tax=0, shipping=0, source='manual',
              **kwargs):
        with A.app.app_context():
            subtotal = sum(quantity * price for _, quantity, price in items)
            sale = A.SalesReceipt(
                customer_id=customer_id,
                date=date or A.datetime(2026, 5, 15, 12, 0),
                total=subtotal + tax + shipping, tax=tax, shipping=shipping,
                source=source, **kwargs)
            A.db.session.add(sale)
            A.db.session.flush()
            sale.receipt_number = str(sale.id)
            for product_id, quantity, price in items:
                A.db.session.add(A.LineItem(
                    receipt_id=sale.id, product_id=product_id, quantity=quantity,
                    price_each=price, total_price=price * quantity))
            A.db.session.commit()
            return sale.id
    return _make


@pytest.fixture
def processed_order(A):
    """One order in the shape ``import_processed_orders`` consumes.

    This is the pipeline's internal contract — every ``process_*`` function
    produces it, so tests that exercise import behaviour rather than a specific
    platform's field mapping start here.
    """
    def _make(external_order_id='EXT-1', external_order_number='1001', **overrides):
        order = {
            'external_order_id': external_order_id,
            'external_order_number': external_order_number,
            'order_date': A.datetime(2026, 6, 1, 10, 0),
            'customer': {
                'name': 'Imported Buyer', 'email': 'imported@example.com',
                'street1': '4 Import Rd', 'city': 'Olympia', 'state': 'WA',
                'postal_code': '98501', 'country': 'US', 'phone': '',
            },
            'items': [{'sku': 'WIDGET-1', 'name': 'Standard widget',
                       'quantity': 1, 'unit_price': A.Decimal('100.00')}],
            'order_total': A.Decimal('108.00'),
            'tax_amount': A.Decimal('8.00'),
            'shipping_amount': A.Decimal('0.00'),
            'shipservice': None, 'tracking': None, 'shipdate': None,
            'customer_notes': '', 'internal_notes': '',
            'customer_data_unavailable': False,
        }
        order.update(overrides)
        return order
    return _make
