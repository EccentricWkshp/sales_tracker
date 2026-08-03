# app.py
import base64
import click
from collections import namedtuple
import csv
from datetime import date, datetime, time as dt_time, timedelta, timezone
from decimal import Decimal, InvalidOperation
from flask import (Flask, abort, render_template, request, redirect, url_for, flash,
                   jsonify, send_from_directory)
from flask.cli import with_appcontext
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import hashlib
import hmac
import io
import json
import logging
from logging.handlers import RotatingFileHandler
from markupsafe import escape, Markup
import os
import pycountry
import random
import re
import requests
import secrets
from sqlalchemy import event, func
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError
from sqlalchemy.orm import joinedload
import sqlite3
import time
from urllib.parse import parse_qs, quote_plus, urlencode, urlparse
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load .env before anything reads os.environ. Optional: production installs keep
# their credentials in the database via the Management page, and .env is only a
# convenience for development. Values already exported win over the file.
try:
    from dotenv import load_dotenv
except ImportError:
    pass
else:
    load_dotenv(os.path.join(BASE_DIR, '.env'), override=False)

app = Flask(__name__)

# Logging Setup — absolute path so the log lands next to app.py no matter what
# working directory the launcher/service starts us in
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

handler = RotatingFileHandler(os.path.join(LOG_DIR, 'sales_tracker.log'),
                              maxBytes=10000000, backupCount=5)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

os.makedirs(app.instance_path, exist_ok=True)

DB_PATH = os.path.join(app.instance_path, 'sales.db')
BACKUP_DIR = os.path.join(app.instance_path, 'backups')
BACKUP_RETAIN = int(os.environ.get('SALES_TRACKER_BACKUP_RETAIN', '14'))

def load_secret_key():
    """FLASK_SECRET_KEY if set, else a persisted random key.

    The key has to survive restarts — a fresh os.urandom(24) each boot would
    invalidate every session cookie and log the user out on every restart.
    """
    from_env = os.environ.get('FLASK_SECRET_KEY')
    if from_env:
        return from_env

    key_path = os.path.join(app.instance_path, 'secret_key')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as fh:
            key = fh.read().strip()
            if key:
                return key

    key = os.urandom(32).hex().encode()
    with open(key_path, 'wb') as fh:
        fh.write(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        # Best effort; Windows ACLs are managed outside the app
        pass
    app.logger.info(f"Generated a new session secret key at {key_path}")
    return key

app.config['SECRET_KEY'] = load_secret_key()

# Defaults to instance/sales.db. Overridable so tests can run against a scratch
# copy instead of live data.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'SALES_TRACKER_DATABASE_URI', 'sqlite:///sales.db?timeout=20')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB cap on uploads

# Session hardening. The app is served over plain HTTP on the LAN, so Secure is
# opt-in via SESSION_COOKIE_SECURE=1 for anyone terminating TLS in front of it.
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=14)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

@event.listens_for(Engine, 'connect')
def _sqlite_pragmas(dbapi_connection, connection_record):
    """Enforce foreign keys and use WAL journaling on every SQLite connection.

    SQLite defaults foreign_keys to OFF, which let bad writes through silently
    (see the import pipeline). WAL lets the app keep reading while a write is in
    flight, which is what the old 'database is locked' retries were papering over.
    """
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.execute('PRAGMA synchronous=NORMAL')
        cursor.execute('PRAGMA busy_timeout=20000')
    finally:
        cursor.close()

def configured_sqlite_path():
    """Filesystem path of the SQLite database actually in use, or None.

    Reads the live config rather than assuming instance/sales.db, so an override
    (tests, a second install) gets backed up instead of the default file.
    """
    uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if not uri.startswith('sqlite:///'):
        return None
    path = uri[len('sqlite:///'):].split('?', 1)[0]
    if not path:
        return None  # sqlite:///:memory: and friends
    if not os.path.isabs(path):
        path = os.path.join(app.instance_path, path)
    return os.path.normpath(path)

def backup_database(db_path=None, backup_dir=None, retain=None, logger=None):
    """Snapshot the SQLite database with the online backup API and prune old copies.

    Safe to call while the app is serving: sqlite3.Connection.backup() takes a
    consistent copy without blocking readers, unlike a file copy.
    Returns the path written, or None if there was nothing to back up.
    """
    db_path = db_path or configured_sqlite_path() or DB_PATH
    backup_dir = backup_dir or BACKUP_DIR
    retain = BACKUP_RETAIN if retain is None else retain
    log = logger or app.logger

    if not os.path.exists(db_path):
        log.warning(f"No database at {db_path}; skipping backup")
        return None

    os.makedirs(backup_dir, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    target = os.path.join(backup_dir, f'sales-{stamp}.db')

    source = sqlite3.connect(db_path)
    try:
        destination = sqlite3.connect(target)
        try:
            source.backup(destination)
        finally:
            destination.close()
        integrity = source.execute('PRAGMA quick_check').fetchone()[0]
    finally:
        source.close()

    if integrity == 'ok':
        log.info(f"Backup written to {target} (quick_check: ok)")
    else:
        log.error(f"Backup written to {target} but quick_check FAILED: {integrity}")

    # Retain the newest `retain` snapshots; names sort chronologically
    snapshots = sorted(
        f for f in os.listdir(backup_dir)
        if f.startswith('sales-') and f.endswith('.db')
    )
    for stale in snapshots[:-retain] if retain > 0 else []:
        try:
            os.remove(os.path.join(backup_dir, stale))
            log.info(f"Pruned old backup {stale}")
        except OSError as e:
            log.warning(f"Could not prune {stale}: {e}")

    return target

login_manager = LoginManager(app)
login_manager.login_view = 'login'
# 'basic', not 'strong': strong protection deletes the session whenever the
# client's IP or user-agent changes, which on a LAN means a laptop moving between
# access points gets silently logged out mid-task. The cookie flags above carry
# the real protection here.
login_manager.session_protection = 'basic'

@click.command('create-admin')
@with_appcontext
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def create_admin(username, password):
    # Create tables if they don't exist
    db.create_all()
    
    user = User.query.filter_by(username=username).first()
    if user:
        click.echo(f"User {username} already exists.")
    else:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        click.echo(f"Admin user {username} created successfully.")

app.cli.add_command(create_admin)

@click.command('backup-db')
@with_appcontext
def backup_db_command():
    """Write a timestamped snapshot of the database to instance/backups."""
    target = backup_database()
    click.echo(f"Backup written to {target}" if target else "Nothing to back up.")

app.cli.add_command(backup_db_command)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Retry decorator
def retry_on_db_lock(max_retries=3, delay=0.1):
    """Retry a call that lost a race for the SQLite write lock.

    SQLAlchemy wraps the driver error, so the raised type is
    sqlalchemy.exc.OperationalError — catching sqlite3.OperationalError (as this
    did originally) never matched and the retry never fired.
    """
    def decorator(func):
        @wraps(func)  # This preserves the original function's metadata
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (OperationalError, sqlite3.OperationalError) as e:
                    if "database is locked" in str(e) and attempt < max_retries - 1:
                        db.session.rollback()
                        time.sleep(delay * (2 ** attempt) + random.uniform(0, 0.1))
                    else:
                        raise
        return wrapper
    return decorator

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CompanyInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    logo = db.Column(db.String(200))  # This will store the path to the logo file

    @classmethod
    def get_info(cls):
        return cls.query.first()

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    email_2 = db.Column(db.String(120))
    billing_address = db.Column(db.String(200), nullable=False)
    shipping_address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    sales = db.relationship('SalesReceipt', back_populates='customer', lazy=True)
    shipstation_mapping = db.relationship('ShipStationCustomerMapping', uselist=False, back_populates='customer')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'company': self.company,
            'email': self.email,
            'email_2': self.email_2,
            'billing_address': self.billing_address,
            'shipping_address': self.shipping_address,
            'phone': self.phone
        }

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    # Counts toward the WA B&O manufacturing classification on the state taxes report
    is_manufactured = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    # Archived products are hidden from new-sale dropdowns; products with sales
    # history can only be archived, never deleted
    archived = db.Column(db.Boolean, nullable=False, default=False, server_default='0')

    # What we pay for it, for margin. Kept separate from `price`, which is what
    # the customer pays and is the only figure any report currently uses.
    cost = db.Column(db.Numeric(10, 2), nullable=False, default=0, server_default='0')
    # Shipping weight in ounces — the unit the carriers' rate tables use
    weight_oz = db.Column(db.Numeric(10, 2), nullable=False, default=0, server_default='0')
    category = db.Column(db.String(60), nullable=False, default='', server_default='')
    vendor = db.Column(db.String(120), nullable=False, default='', server_default='')
    # Free text: build notes, substitutions, anything that does not fit a column
    notes = db.Column(db.Text, nullable=False, default='', server_default='')

    attachments = db.relationship('ProductAttachment', back_populates='product',
                                  cascade='all, delete-orphan', lazy=True)

    @property
    def margin(self):
        """Price minus cost, or None when no cost has been recorded."""
        if not self.cost:
            return None
        return Decimal(self.price) - Decimal(self.cost)

    def to_dict(self):
        margin = self.margin
        return {
            'id': self.id,
            'sku': self.sku,
            'description': self.description,
            'price': float(self.price),
            'is_manufactured': self.is_manufactured,
            'archived': self.archived,
            'cost': float(self.cost or 0),
            'weight_oz': float(self.weight_oz or 0),
            'category': self.category or '',
            'vendor': self.vendor or '',
            'notes': self.notes or '',
            'margin': float(margin) if margin is not None else None,
            'attachment_count': len(self.attachments),
        }

class ProductAttachment(db.Model):
    """A file that belongs to a product — typically a datasheet to ship with it.

    The uploaded bytes live under instance/product_attachments/ rather than
    static/, so they are only reachable through a login-required route. The name
    on disk is generated: an operator's filename would otherwise decide a path.
    """
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False, index=True)
    stored_name = db.Column(db.String(120), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    content_type = db.Column(db.String(100), nullable=False, default='', server_default='')
    size_bytes = db.Column(db.Integer, nullable=False, default=0, server_default='0')
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    # Offered on the receipt's print page when the product is on that sale
    print_with_receipt = db.Column(db.Boolean, nullable=False, default=True, server_default='1')

    product = db.relationship('Product', back_populates='attachments')

    def to_dict(self):
        return {
            'id': self.id,
            'product_id': self.product_id,
            'name': self.original_name,
            'content_type': self.content_type,
            'size_bytes': self.size_bytes,
            'size_label': human_size(self.size_bytes),
            'uploaded_at': self.uploaded_at.strftime('%Y-%m-%d') if self.uploaded_at else '',
            'print_with_receipt': self.print_with_receipt,
            'url': url_for('download_product_attachment', id=self.id),
        }

class SalesReceipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Three identifiers, three jobs. They are not interchangeable — see
    # apply_order_to_sale, and migrations/rename_order_identifier_columns.py for
    # the history behind the old names.
    #
    # Sales Tracker's own receipt number. Always the receipt's id, whether the
    # sale was entered by hand or imported.
    receipt_number = db.Column(db.String(50), nullable=True)
    # The selling platform's human-facing order number ("#1001", "4094194072").
    # Display only, never a match key: older rows hold a ShipStation orderId here
    # instead, and it is not unique in the live database (the table was rebuilt
    # without the constraint), so the model must not claim it is.
    external_order_number = db.Column(db.String(50), nullable=True)
    # Which system this receipt came from: 'shipstation', 'shippo', 'shopify',
    # 'manual', or NULL for rows predating this column
    source = db.Column(db.String(20), nullable=True, index=True)
    # That platform's internal order id. (source, external_order_id) is the
    # duplicate-detection key for re-imports.
    external_order_id = db.Column(db.String(64), nullable=True, index=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    #customer_name = db.relationship('Customer', backref='sales_receipts', lazy=True)
    customer = db.relationship('Customer', back_populates='sales', lazy=True)
    shipservice = db.Column(db.String(50))
    tracking = db.Column(db.String(50))
    shipdate = db.Column(db.Date)
    date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    total = db.Column(db.Float, nullable=False)
    tax = db.Column(db.Float, nullable=False)
    shipping = db.Column(db.Float, nullable=False)
    line_items = db.relationship('LineItem', backref='sales_receipt', lazy=True)
    customer_notes = db.Column(db.String(500)) # Notes visible to customer
    internal_notes = db.Column(db.String(500)) # Internal notes

    def to_dict(self):
        return {
            'id': self.id,
            'receipt_number': self.receipt_number,        # ours
            'external_order_number': self.external_order_number,  # the platform's, human-facing
            'external_order_id': self.external_order_id,  # the platform's, internal
            'source': self.source,
            'customer_id': self.customer_id,
            'customer_name': self.customer.name if self.customer else None,
            'shipservice': self.shipservice if self.shipservice else None,
            'tracking': self.tracking if self.tracking else None,
            'shipdate': self.shipdate.strftime('%m-%d-%Y') if self.shipdate else None,
            'date': self.date.strftime('%m-%d-%Y'),
            'total': self.total,
            'tax': self.tax,
            'shipping': self.shipping,
            'line_items': [item.to_dict() for item in self.line_items],
            'customer_notes': self.customer_notes,
            'internal_notes': self.internal_notes
        }

class LineItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_id = db.Column(db.Integer, db.ForeignKey('sales_receipt.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_each = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    product = db.relationship('Product')

    def to_dict(self):
        return {
            'id': self.id,
            'receipt_id': self.receipt_id,
            'product_id': self.product_id,
            'quantity': self.quantity,
            'price_each': self.price_each,
            'total_price': self.total_price,
            'product': self.product.to_dict() if self.product else None
        }

class ShipStationCustomerMapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    shipstation_customer_id = db.Column(db.String(50), unique=True, nullable=False)
    customer = db.relationship('Customer', back_populates='shipstation_mapping')

class ShipStationCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(100), nullable=False)
    api_secret = db.Column(db.String(100), nullable=False)
    enabled = db.Column(db.Boolean, default=False, nullable=False)

class WooCommerceCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(100), nullable=False)
    api_secret = db.Column(db.String(100), nullable=False)
    enabled = db.Column(db.Boolean, default=False, nullable=False)

class ShippoCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(100), nullable=False)
    enabled = db.Column(db.Boolean, default=False, nullable=False)

class ShopifyCredentials(db.Model):
    """Credentials for one Shopify store, supporting both auth routes.

    Legacy custom app (auth_mode='token'):
        api_key    — Admin API access token (shpat_…), used directly and forever
        api_secret — the app's API secret key, verifies webhook HMACs

    Dev Dashboard app (auth_mode='client_credentials'):
        client_id / client_secret — exchanged for a 24-hour access token
        access_token / access_token_expires_at — the cached result of that
            exchange, persisted so a restart does not force a new round trip
        client_secret also verifies webhook HMACs for this route

    shop_domain is the *.myshopify.com host, not the customer-facing domain.
    """
    id = db.Column(db.Integer, primary_key=True)
    shop_domain = db.Column(db.String(120), nullable=False, default='', server_default='')
    auth_mode = db.Column(db.String(20), nullable=False, default='token', server_default='token')

    api_key = db.Column(db.String(120), nullable=False)
    api_secret = db.Column(db.String(120), nullable=False, default='', server_default='')

    client_id = db.Column(db.String(120), nullable=False, default='', server_default='')
    client_secret = db.Column(db.String(120), nullable=False, default='', server_default='')
    access_token = db.Column(db.String(255), nullable=False, default='', server_default='')
    access_token_expires_at = db.Column(db.DateTime, nullable=True)

    enabled = db.Column(db.Boolean, default=False, nullable=False)
    webhooks_enabled = db.Column(db.Boolean, default=False, nullable=False, server_default='0')

class OAuthCredentialsMixin:
    """Token columns shared by every marketplace that needs OAuth 2.0 consent.

    Etsy and eBay differ in which fields identify the app and in their endpoints,
    but not in what has to be persisted: a short-lived access token, the
    long-lived refresh token that renews it, and the one-shot state the consent
    redirect has to carry across the round trip.

    Tokens are Text rather than String because eBay user tokens run to a few
    thousand characters — a String(255) would truncate silently on some backends.
    """
    access_token = db.Column(db.Text, nullable=False, default='', server_default='')
    refresh_token = db.Column(db.Text, nullable=False, default='', server_default='')
    access_token_expires_at = db.Column(db.DateTime, nullable=True)
    refresh_token_expires_at = db.Column(db.DateTime, nullable=True)
    # CSRF nonce and PKCE verifier, held only between "Connect" and the callback
    oauth_state = db.Column(db.String(64), nullable=False, default='', server_default='')
    oauth_verifier = db.Column(db.String(128), nullable=False, default='', server_default='')

class EtsyCredentials(OAuthCredentialsMixin, db.Model):
    """One Etsy shop. `client_id` is the app's keystring, `client_secret` its
    shared secret. `shop_id` is the numeric shop id the receipts endpoint needs —
    it is discovered automatically once connected."""
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(120), nullable=False, default='', server_default='')
    client_secret = db.Column(db.String(120), nullable=False, default='', server_default='')
    shop_id = db.Column(db.String(50), nullable=False, default='', server_default='')
    enabled = db.Column(db.Boolean, default=False, nullable=False)

class EbayCredentials(OAuthCredentialsMixin, db.Model):
    """One eBay seller account.

    `client_id` is the App ID (Client ID) and `client_secret` the Cert ID.
    `ru_name` is eBay's RuName — the *alias* for your redirect URI, which is what
    the authorize and token calls send instead of the URL itself.
    """
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(120), nullable=False, default='', server_default='')
    client_secret = db.Column(db.String(120), nullable=False, default='', server_default='')
    ru_name = db.Column(db.String(200), nullable=False, default='', server_default='')
    # Sandbox has entirely different hosts; keeping it a flag avoids a second row
    sandbox = db.Column(db.Boolean, default=False, nullable=False, server_default='0')
    enabled = db.Column(db.Boolean, default=False, nullable=False)

class PendingOrder(db.Model):
    """An imported order held back because the platform withheld the buyer's details.

    Shopify returns null for name, email, phone and address unless the app is
    approved for protected customer data — for an admin-created custom app that
    depends on the store's plan. Such an order has usable money and line items but
    nobody to attach them to, and an address with no city or ZIP cannot be
    classified for state tax reporting.

    Rather than create a half-identified sale that quietly lands in the 'Unknown'
    bucket, the order is parked here until someone supplies the customer. Nothing
    in this table counts toward any total.
    """
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(20), nullable=False, index=True)
    external_order_id = db.Column(db.String(64), nullable=False, index=True)
    external_order_number = db.Column(db.String(50))
    order_date = db.Column(db.DateTime)
    total = db.Column(db.Float, nullable=False, default=0)
    tax = db.Column(db.Float, nullable=False, default=0)
    shipping = db.Column(db.Float, nullable=False, default=0)
    shipservice = db.Column(db.String(50))
    tracking = db.Column(db.String(50))
    shipdate = db.Column(db.Date)
    customer_notes = db.Column(db.String(500))
    internal_notes = db.Column(db.String(500))
    # The full processed order as JSON, so the receipt can be built on completion
    payload = db.Column(db.Text, nullable=False, default='{}')
    imported_at = db.Column(db.DateTime, default=datetime.now)

    __table_args__ = (
        db.UniqueConstraint('source', 'external_order_id', name='uq_pending_order_source_ext'),
    )

    def items(self):
        try:
            return json.loads(self.payload or '{}').get('items', [])
        except ValueError:
            return []

    def location_hint(self):
        """Whatever partial location the platform did share, e.g. 'CA, US'.

        Shopify tends to withhold street, city and ZIP but still return
        province_code and country_code. Not enough to classify a sale, but a
        useful head start when filling in the customer.
        """
        try:
            customer = json.loads(self.payload or '{}').get('customer', {})
        except ValueError:
            return ''
        parts = [customer.get('state'), customer.get('country')]
        return ', '.join(part for part in parts if part)

    def to_dict(self):
        return {
            'id': self.id,
            'source': self.source,
            'external_order_id': self.external_order_id,
            'external_order_number': self.external_order_number,
            'order_date': self.order_date.strftime('%Y-%m-%d') if self.order_date else None,
            'total': float(self.total),
            'tax': float(self.tax),
            'shipping': float(self.shipping),
            'shipservice': self.shipservice,
            'tracking': self.tracking,
            'shipdate': self.shipdate.strftime('%Y-%m-%d') if self.shipdate else None,
            'customer_notes': self.customer_notes,
            'location_hint': self.location_hint(),
            'items': ', '.join(
                f"{item.get('quantity')}x {item.get('sku')}" for item in self.items()),
            'imported_at': self.imported_at.strftime('%Y-%m-%d') if self.imported_at else None,
        }

class BankTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    credit_debit = db.Column(db.String(10))  # 'Credit' or 'Debit'
    transaction_type = db.Column(db.String(50))  # 'ACH Credit', 'POS', 'ACH Debit', etc.
    category = db.Column(db.String(100))
    notes = db.Column(db.String(500))
    check_number = db.Column(db.String(20))
    receipt_id = db.Column(db.Integer, db.ForeignKey('sales_receipt.id'), nullable=True)
    imported_at = db.Column(db.DateTime, default=datetime.utcnow)
    receipt = db.relationship('SalesReceipt', backref='bank_transactions') # Relationship to SalesReceipt

    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.strftime('%Y-%m-%d'),
            'description': self.description,
            'amount': float(self.amount),
            'credit_debit': self.credit_debit,
            'transaction_type': self.transaction_type,
            'category': self.category,
            'notes': self.notes,
            'check_number': self.check_number,
            'receipt_id': self.receipt_id,
            'receipt_number': f"#{self.receipt.id}" if self.receipt else None
        }

# Filters
@app.template_filter('nl2br')
def nl2br(value):
    if value is None:
        return ''
    return Markup(escape(value).replace('\n', Markup('<br>\n')))

@app.template_filter('maps_query')
def maps_query(value):
    """Collapse a multi-line address into a single URL-safe Google Maps query.

    Addresses are user/import supplied, so they must never be interpolated into
    an href unescaped — newlines and quotes would break out of the attribute.
    """
    return quote_plus(' '.join((value or '').split()))

@app.template_filter('cleaned')
def cleaned(value):
    # Handle None and variations of "None"
    if value is None or str(value).strip().lower() == 'none':
        return ""

    # Serialize value to JSON with ensure_ascii=False to keep Unicode characters
    json_value = json.dumps(value, ensure_ascii=False)

    # Escape backslashes and single quotes for JavaScript
    json_value = json_value.replace("\\", "\\\\").replace("'", "\\'")

    # Remove enclosing double quotes
    if json_value.startswith('"') and json_value.endswith('"'):
        json_value = json_value[1:-1]

    return Markup(json_value)

# Loaders
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    total_revenue = db.session.query(func.sum(SalesReceipt.total)).scalar() or 0
    total_sales = SalesReceipt.query.count()
    total_customers = Customer.query.count()
    recent_sales = SalesReceipt.query.options(joinedload(SalesReceipt.customer)) \
        .order_by(SalesReceipt.date.desc()).limit(10).all()
    company_info = CompanyInfo.get_info()

    return render_template('index.html',
                           pending_order_count=PendingOrder.query.count(),
                           total_revenue=total_revenue,
                           total_sales=total_sales,
                           total_customers=total_customers,
                           recent_sales=recent_sales,
                           company_info=company_info,
                           enabled_integrations=enabled_integration_cards())

# Font Awesome classes for the dashboard cards, by integration key
INTEGRATION_ICONS = {
    'shopify': 'fab fa-shopify',
    'shipstation': 'fas fa-box-open',
    'shippo': 'fas fa-shipping-fast',
    'woocommerce': 'fab fa-wordpress',
    'etsy': 'fab fa-etsy',
    'ebay': 'fab fa-ebay',
}

def enabled_integration_cards():
    """The dashboard's import cards, one per switched-on integration."""
    return [
        {
            'key': spec.key,
            'label': spec.label,
            'icon': INTEGRATION_ICONS.get(spec.key, 'fas fa-plug'),
            'fetch_url': url_for('fetch_integration_orders', key=spec.key),
        }
        for spec in integration_specs() if spec.is_enabled()
    ]

@app.route('/login', methods=['GET', 'POST'])
def login():
    next_page = request.args.get('next')
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=False)
            flash('Logged in successfully.', 'success')
            # Only redirect to same-origin paths, never an attacker-supplied host
            parsed = urlparse(next_page or '')
            if next_page and not parsed.netloc and not parsed.scheme and next_page.startswith('/'):
                return redirect(next_page)
            else:
                return redirect(url_for('index'))
        else:
            app.logger.warning(f"Failed login for username '{username}' from {request.remote_addr}")
            flash('Invalid username or password', 'error')

    company_info = CompanyInfo.get_info()

    return render_template('login.html', next=next_page, company_info=company_info)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

class IntegrationSpec:
    """Everything the app needs to know about one order source.

    Adding a marketplace should be: write its `fetch` and `process` functions,
    declare a credentials model, and append one entry to INTEGRATIONS. The
    Management form, the environment-variable overrides, the dashboard card, the
    fetch route and the OAuth round trip are all driven from here rather than
    hand-written per platform, which is what they used to be.

    key           value stored in SalesReceipt.source; also the URL segment
    form_prefix   Management field prefix (legacy names differ from the key)
    secret_fields never echoed back to the browser
    plain_fields  safe to render
    bool_fields   checkboxes beyond the standard `enabled`
    env_fields    {field: (VAR, VAR2, ...)} — set any and it wins over the database
    fetch         (credentials, start_date, end_date) -> raw platform orders
    process       (raw orders) -> the shape import_processed_orders wants
    oauth         OAuthSpec when the platform needs a consent round trip
    """

    def __init__(self, key, label, model, form_prefix=None, secret_fields=(),
                 plain_fields=(), bool_fields=(), env_fields=None,
                 fetch=None, process=None, enrich=None, oauth=None, blurb='',
                 empty_message=None, field_labels=None, field_hints=None):
        self.key = key
        self.label = label
        self.model = model
        self.form_prefix = form_prefix or key
        self.secret_fields = tuple(secret_fields)
        self.plain_fields = tuple(plain_fields)
        self.bool_fields = tuple(bool_fields)
        self.env_fields = env_fields or {}
        self.fetch = fetch
        self.process = process
        # (credentials) -> per-order callback, for platforms needing a second
        # call per order. ShipStation's shipment lookup is the only one so far.
        self.enrich = enrich
        self.oauth = oauth
        self.blurb = blurb
        self.empty_message = empty_message
        # Storage stays generic (client_id/client_secret) because the OAuth
        # machinery is shared, but each marketplace names those things its own
        # way — Etsy says keystring and shared secret, eBay says App ID and Cert
        # ID. Show the operator the words their developer console uses.
        self.field_labels = field_labels or {}
        self.field_hints = field_hints or {}

    @property
    def fields(self):
        return self.secret_fields + self.plain_fields

    def label_for(self, field):
        return self.field_labels.get(field) or field.replace('_', ' ').title()

    def hint_for(self, field):
        return self.field_hints.get(field, '')

    def credentials(self):
        return self.model.query.first()

    def env_value(self, field):
        for name in self.env_fields.get(field, ()):
            value = (os.environ.get(name) or '').strip()
            if value:
                return value
        return ''

    def setting(self, credentials, field):
        """Resolve one credential field: environment first, then the database."""
        return self.env_value(field) or (getattr(credentials, field, '') or '').strip()

    def is_enabled(self):
        record = self.credentials()
        return bool(record and record.enabled)

# Populated at the bottom of the integrations section, once each platform's
# fetch/process functions exist. Keyed by SalesReceipt.source value.
INTEGRATIONS = {}

def integration_specs():
    """Registry entries in display order."""
    return list(INTEGRATIONS.values())

def _save_integration_credentials(form):
    """Apply the Management form to every integration's stored credentials.

    Secret fields render blank with a "saved" hint, so a blank submission means
    "leave unchanged" — secrets never round-trip through the page HTML.
    """
    for spec in integration_specs():
        record = spec.credentials()
        prefix = spec.form_prefix
        submitted = {
            field: (form.get(f'{prefix}_{field}') or '').strip()
            for field in spec.fields
        }
        enabled = f'{prefix}_enabled' in form
        flags = {field: f'{prefix}_{field}' in form for field in spec.bool_fields}

        if record is None:
            # Don't create an empty row for an integration that was never touched
            if not any(submitted.values()) and not enabled:
                continue
            record = spec.model(**{field: submitted.get(field, '') for field in spec.fields})
            record.enabled = enabled
            for field, value in flags.items():
                setattr(record, field, value)
            db.session.add(record)
            continue

        for field in spec.secret_fields:
            if submitted[field]:
                setattr(record, field, submitted[field])
        for field in spec.plain_fields:
            setattr(record, field, submitted[field])
        record.enabled = enabled
        for field, value in flags.items():
            setattr(record, field, value)

        # Re-authorising is required when the app identity itself changes
        if spec.oauth and any(submitted.get(field) for field in ('client_id', 'client_secret')):
            clear_oauth_tokens(record)

    shopify = ShopifyCredentials.query.first()
    if shopify:
        shopify.webhooks_enabled = 'shopify_webhooks_enabled' in form

        requested_mode = (form.get('shopify_auth_mode') or '').strip()
        if requested_mode in ('token', 'client_credentials'):
            if requested_mode != shopify.auth_mode:
                # Switching routes invalidates any token cached from the old one
                shopify.access_token = ''
                shopify.access_token_expires_at = None
            shopify.auth_mode = requested_mode

        # A new client id/secret means the cached 24-hour token no longer matches
        # the credentials that produced it
        if (form.get('shopify_client_id') or '').strip() or (form.get('shopify_client_secret') or '').strip():
            shopify.access_token = ''
            shopify.access_token_expires_at = None

@app.route('/management', methods=['GET', 'POST'])
@login_required
def management():
    company_info = CompanyInfo.get_info()

    if request.method == 'POST':
        logo_path = company_info.logo if company_info else None
        file = request.files.get('logo')
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                logo_path = f'/static/uploads/{filename}'
            else:
                flash('Logo must be a PNG, JPG, JPEG or GIF file. Other settings were saved.', 'warning')

        fields = {
            'name': (request.form.get('name') or '').strip(),
            'address': (request.form.get('address') or '').strip(),
            'phone': (request.form.get('phone') or '').strip(),
            'email': (request.form.get('email') or '').strip(),
            'logo': logo_path,
        }
        if company_info:
            for key, value in fields.items():
                setattr(company_info, key, value)
        else:
            db.session.add(CompanyInfo(**fields))

        _save_integration_credentials(request.form)

        try:
            db.session.commit()
            flash('Settings updated successfully.', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Error updating settings: {e}")
            flash('Error updating settings.', 'error')

        return redirect(url_for('management'))

    shopify = ShopifyCredentials.query.first()
    return render_template('management.html',
                         company_info=company_info,
                         integrations=integration_views(),
                         shopify_credentials=shopify,
                         shopify_auth_mode=shopify_auth_mode(shopify) if shopify else 'token',
                         shopify_shop_domain=shopify_shop_domain(shopify) if shopify else '',
                         shopify_token_expires_at=shopify.access_token_expires_at if shopify else None,
                         webhook_url=url_for('shopify_webhook', _external=True))

def integration_views():
    """One render-ready dict per integration, so the template stays declarative.

    Deliberately carries no secret values — only whether each field is set, and
    whether an environment variable is supplying it. See the note at the top of
    management.html about why credentials never reach the page.
    """
    views = []
    for spec in integration_specs():
        credentials = spec.credentials()
        views.append({
            'key': spec.key,
            'label': spec.label,
            'blurb': spec.blurb,
            'prefix': spec.form_prefix,
            'enabled': bool(credentials and credentials.enabled),
            'has_importer': spec.fetch is not None,
            'secret_fields': spec.secret_fields,
            'plain_fields': spec.plain_fields,
            'saved': {field: bool((getattr(credentials, field, '') or '').strip())
                      for field in spec.fields} if credentials else {},
            # Not 'values': Jinja resolves attributes before items, so view.values
            # would hand the template dict.values instead of this mapping
            'field_values': {field: (getattr(credentials, field, '') or '')
                             for field in spec.plain_fields} if credentials else {},
            'flags': {field: bool(getattr(credentials, field, False))
                      for field in spec.bool_fields} if credentials else {},
            # Why editing a field might have no effect
            'from_env': {field: bool(spec.env_value(field)) for field in spec.fields},
            # bool_fields included: their checkbox needs a label too
            'labels': {field: spec.label_for(field)
                       for field in spec.fields + spec.bool_fields},
            'hints': {field: spec.hint_for(field) for field in spec.fields},
            'oauth': (dict(oauth_status(spec), docs_url=spec.oauth.docs_url)
                      if spec.oauth else None),
        })
    return views

@app.route('/state_taxes')
@login_required
def state_taxes():
    # The grid loads its data from /api/state_taxes_data
    return render_template('state_taxes.html', company_info=CompanyInfo.get_info())

@app.route('/api/state_taxes_data')
@login_required
def get_state_taxes_data():
    year = request.args.get('year', type=int)
    quarter = (request.args.get('quarter') or '').upper()
    start = request.args.get('start', type=int)
    end = request.args.get('end', type=int)

    quarter_start_months = {'Q1': 1, 'Q2': 4, 'Q3': 7, 'Q4': 10}
    if year is None or quarter not in quarter_start_months:
        return jsonify({'error': 'year (integer) and quarter (Q1-Q4) are required'}), 400

    start_month = quarter_start_months[quarter]
    start_date = datetime(year, start_month, 1)
    # Half-open range so times on the quarter's last day are never excluded
    if quarter == 'Q4':
        end_date = datetime(year + 1, 1, 1)
    else:
        end_date = datetime(year, start_month + 3, 1)

    query = SalesReceipt.query.filter(
        SalesReceipt.date >= start_date,
        SalesReceipt.date < end_date
    ).options(
        joinedload(SalesReceipt.customer),
        joinedload(SalesReceipt.line_items).joinedload(LineItem.product)
    ).order_by(SalesReceipt.date, SalesReceipt.id)

    total_count = query.count()

    # Pagination is optional; without start/end the whole quarter is returned
    # so the report totals always cover every sale
    if start is not None or end is not None:
        start = start or 0
        query = query.offset(start)
        if end is not None:
            query = query.limit(max(end - start, 0))
    sales = query.all()

    data = []
    for sale in sales:
        manufacturing = sum(item.total_price for item in sale.line_items if item.product.is_manufactured)
        retail = sum(item.total_price for item in sale.line_items)
        items = format_items(sale.line_items)

        data.append({
            'date': sale.date.strftime('%Y-%m-%d'),
            'id': sale.id,
            'customer_id': sale.customer_id,
            'name': sale.customer.name,
            'state': get_state_info(sale.customer.shipping_address),
            'manufacturing': float(manufacturing),
            'retail': float(retail),
            'shipping': float(sale.shipping),
            'items': items
        })

    return jsonify({
        'rows': data,
        'lastRow': total_count
    })

@app.route('/customers')
@login_required
def customers():
    customers = Customer.query.all()
    company_info = CompanyInfo.get_info()

    return render_template('customers.html', customers=customers, company_info=company_info)

def _placeholder_email():
    """Customer.email is unique and NOT NULL, so customers without a real address
    (common on marketplace imports) get a unique synthetic one. The UI hides these
    — see emailValueFormatter in script.js."""
    email = f"placeholder_{uuid.uuid4().hex}@example.com"
    app.logger.warning(f"Missing customer email. Generated placeholder: {email}")
    return email

def _parse_customer_payload(data, existing=None):
    """Validate a customer add/edit payload; returns (fields, error_message).

    Every field is read with .get() so a partial payload is a 400 with a readable
    message rather than a KeyError 500. A blank email keeps the customer's current
    placeholder (on edit) or mints a new one (on add) instead of violating the
    unique NOT NULL constraint.
    """
    name = (data.get('name') or '').strip()
    if not name:
        return None, 'Name is required'

    email = (data.get('email') or '').strip()
    if not email:
        if existing and existing.email:
            email = existing.email
        else:
            email = _placeholder_email()

    return {
        'name': name,
        'company': (data.get('company') or '').strip(),
        'email': email,
        'email_2': (data.get('email_2') or '').strip() or None,
        'phone': (data.get('phone') or '').strip(),
        'billing_address': (data.get('billing_address') or '').strip(),
        'shipping_address': (data.get('shipping_address') or '').strip(),
    }, None

@app.route('/customers/add', methods=['POST'])
@login_required
def add_customer():
    fields, error = _parse_customer_payload(request.json or {})
    if error:
        return jsonify({'success': False, 'message': error, 'category': 'error'}), 400

    new_customer = Customer(**fields)
    db.session.add(new_customer)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f"A customer with the email {fields['email']} already exists.",
            'category': 'error'
        }), 409
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error adding customer {fields['name']}: {e}")
        return jsonify({'success': False, 'message': 'Error adding customer.', 'category': 'error'}), 400

    app.logger.info(f"Successfully added customer {new_customer.name}")
    return jsonify({
        'success': True,
        'id': new_customer.id,
        'message': f'Customer {new_customer.name} added successfully.',
        'category': 'success'
    }), 200

@app.route('/customers/edit/<int:id>', methods=['POST'])
@login_required
def edit_customer(id):
    customer = db.get_or_404(Customer, id)
    fields, error = _parse_customer_payload(request.json or {}, existing=customer)
    if error:
        return jsonify({'success': False, 'message': error, 'category': 'error'}), 400

    for key, value in fields.items():
        setattr(customer, key, value)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f"Another customer already uses the email {fields['email']}.",
            'category': 'error'
        }), 409
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error updating customer {id}: {e}")
        return jsonify({'success': False, 'message': 'Error updating customer.', 'category': 'error'}), 400

    return jsonify({'success': True, 'message': 'Customer updated successfully.', 'category': 'success'}), 200

@app.route('/customers/get/<int:id>')
@login_required
def get_customer(id):
    customer = Customer.query.get_or_404(id)
    return jsonify({
        'id': customer.id,
        'name': customer.name,
        'company': customer.company,
        'email': customer.email,
        'email_2': customer.email_2,
        'phone': customer.phone,
        'billing_address': customer.billing_address,
        'shipping_address': customer.shipping_address
    })

@app.route('/customers/view/<int:id>')
@login_required
def view_customer(id):
    customer = Customer.query.get_or_404(id)
    orders = SalesReceipt.query.filter_by(customer_id=id).order_by(SalesReceipt.date.desc()).all()
    company_info = CompanyInfo.get_info()
    
    return render_template('view_customer.html', customer=customer, orders=orders, company_info=company_info)

@app.route('/customers/delete/<int:id>', methods=['POST'])
@login_required
def delete_customer(id):
    customer = Customer.query.get_or_404(id)
    #db.session.delete(customer)
    #db.session.commit()
    #return jsonify({'success': True})

    try:
        db.session.delete(customer)
        db.session.commit()
        #return jsonify({"success": f"Deleted {customer.name}"}), 200
        return jsonify({'success': True, 'message': f'{customer.name} deleted successfully.', 'category': 'success'}), 200
    except IntegrityError:
        db.session.rollback()
        # Hide this error because we have a better error display method through showFlashMessage
        #app.logger.error(f"Error deleting customer: {customer.name}")
        #return jsonify({"error": f"Cannot delete {customer.name}: associated sales receipts"}), 400
        return jsonify({'success': False, 'message': f'Unable to delete {customer.name}: associated sales receipts.', 'category': 'error'}), 400

@app.route('/customers/merge', methods=['POST'])
@login_required
def merge_customers_route():
    data = request.json
    customer_id1 = data.get('customer_id1')
    customer_id2 = data.get('customer_id2')

    if not customer_id1 or not customer_id2:
        return jsonify({'success': False, 'message': 'Both customer IDs are required.'}), 400

    success, message = merge_customers(customer_id1, customer_id2)

    if success:
        return jsonify({'success': True, 'message': message}), 200
    else:
        return jsonify({'success': False, 'message': message}), 400

@app.route('/api/customers')
@login_required
def get_customers():
    customers = Customer.query.all()
    customers_dict = [customer.to_dict() for customer in customers]

    return jsonify(customers_dict)

@app.route('/api/customer_orders/<int:id>')
@login_required
def get_customer_orders(id):
    orders = SalesReceipt.query.filter_by(customer_id=id).options(
        joinedload(SalesReceipt.line_items).joinedload(LineItem.product)
    ).order_by(SalesReceipt.date.desc()).all()
    
    order_data = []
    for order in orders:
        order_data.append({
            'id': order.id,
            'date': order.date.strftime('%Y-%m-%d'),
            'shipservice': order.shipservice,
            'tracking': order.tracking,
            'shipdate': order.shipdate,
            'total': float(order.total),
            'tax': float(order.tax),
            'shipping': float(order.shipping),
            'items': ', '.join([f"{item.quantity}x {item.product.sku}" for item in order.line_items])
        })
    
    return jsonify(order_data)
        
@app.route('/products')
@login_required
def products():
    # The grid loads its data from /api/products
    return render_template('products.html', company_info=CompanyInfo.get_info())

def _parse_product_number(data, field, label):
    """Parse an optional money/weight field. Returns (Decimal, error_message)."""
    raw = str(data.get(field, '') or '').replace('$', '').replace(',', '').strip()
    if not raw:
        return Decimal('0'), None
    try:
        value = Decimal(raw)
    except InvalidOperation:
        return None, f'{label} must be a number'
    if value < 0:
        return None, f'{label} cannot be negative'
    return value, None

def _parse_product_payload(data):
    """Validate a product add/edit payload; returns (fields, error_message)."""
    sku = (data.get('sku') or '').strip()
    description = (data.get('description') or '').strip()
    if not sku:
        return None, 'SKU is required'
    if len(sku) > 20:
        return None, 'SKU must be 20 characters or fewer'
    if not description:
        return None, 'Description is required'
    if len(description) > 200:
        return None, 'Description must be 200 characters or fewer'
    try:
        price = Decimal(str(data.get('price', '')).replace('$', '').replace(',', '').strip())
    except InvalidOperation:
        return None, 'Price must be a number'
    if price < 0:
        return None, 'Price cannot be negative'

    cost, error = _parse_product_number(data, 'cost', 'Cost')
    if error:
        return None, error
    weight, error = _parse_product_number(data, 'weight_oz', 'Weight')
    if error:
        return None, error

    return {
        'sku': sku,
        'description': description,
        'price': price,
        'is_manufactured': bool(data.get('is_manufactured', False)),
        'archived': bool(data.get('archived', False)),
        'cost': cost,
        'weight_oz': weight,
        'category': (data.get('category') or '').strip()[:60],
        'vendor': (data.get('vendor') or '').strip()[:120],
        'notes': (data.get('notes') or '').strip(),
    }, None

# ---------------------------------------------------------------------------
# Product attachments — datasheets and similar, printed alongside a receipt
# ---------------------------------------------------------------------------

PRODUCT_ATTACHMENT_DIR = os.path.join(app.instance_path, 'product_attachments')
ATTACHMENT_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'csv',
                         'doc', 'docx', 'xls', 'xlsx'}

def human_size(num_bytes):
    size = float(num_bytes or 0)
    for unit in ('B', 'KB', 'MB'):
        if size < 1024 or unit == 'MB':
            return f'{size:.0f} {unit}' if unit == 'B' else f'{size:.1f} {unit}'
        size /= 1024

def attachment_extension(filename):
    return filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

@app.route('/products/<int:id>/attachments', methods=['POST'])
@login_required
def upload_product_attachment(id):
    """Attach a file to a product. Multipart, one or more files at a time."""
    product = Product.query.get_or_404(id)
    files = [f for f in request.files.getlist('files') if f and f.filename]
    if not files:
        return jsonify({'success': False, 'error': 'Choose a file to upload.'}), 400

    os.makedirs(PRODUCT_ATTACHMENT_DIR, exist_ok=True)
    saved, rejected = [], []
    for file in files:
        extension = attachment_extension(file.filename)
        if extension not in ATTACHMENT_EXTENSIONS:
            rejected.append(f'{file.filename} (.{extension or "no extension"} not allowed)')
            continue

        # The name on disk is ours, never the operator's — a filename is not a
        # safe path component even after secure_filename
        stored_name = f'{uuid.uuid4().hex}.{extension}'
        path = os.path.join(PRODUCT_ATTACHMENT_DIR, stored_name)
        file.save(path)

        attachment = ProductAttachment(
            product_id=product.id,
            stored_name=stored_name,
            original_name=secure_filename(file.filename)[:255] or f'file.{extension}',
            content_type=(file.mimetype or '')[:100],
            size_bytes=os.path.getsize(path),
        )
        db.session.add(attachment)
        saved.append(attachment)

    if not saved:
        return jsonify({'success': False,
                        'error': 'Nothing uploaded. ' + '; '.join(rejected)}), 400

    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        for attachment in saved:
            _remove_attachment_file(attachment.stored_name)
        app.logger.error(f'Could not record attachments for product {id}: {e}')
        return jsonify({'success': False, 'error': 'Could not save the attachment.'}), 500

    return jsonify({'success': True,
                    'attachments': [a.to_dict() for a in product.attachments],
                    'rejected': rejected})

def _remove_attachment_file(stored_name):
    """Delete the bytes, tolerating a file already gone."""
    try:
        os.remove(os.path.join(PRODUCT_ATTACHMENT_DIR, stored_name))
    except OSError:
        pass

@app.route('/products/attachments/<int:id>')
@login_required
def download_product_attachment(id):
    attachment = ProductAttachment.query.get_or_404(id)
    return send_from_directory(
        PRODUCT_ATTACHMENT_DIR, attachment.stored_name,
        # inline so a PDF opens in the browser's viewer, ready to print
        as_attachment=False, download_name=attachment.original_name)

@app.route('/products/attachments/<int:id>/delete', methods=['POST'])
@login_required
def delete_product_attachment(id):
    attachment = ProductAttachment.query.get_or_404(id)
    stored_name = attachment.stored_name
    db.session.delete(attachment)
    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f'Could not delete attachment {id}: {e}')
        return jsonify({'success': False, 'error': 'Could not delete that file.'}), 500
    _remove_attachment_file(stored_name)
    return jsonify({'success': True})

@app.route('/products/attachments/<int:id>/print_flag', methods=['POST'])
@login_required
def set_attachment_print_flag(id):
    attachment = ProductAttachment.query.get_or_404(id)
    attachment.print_with_receipt = bool((request.json or {}).get('print_with_receipt'))
    db.session.commit()
    return jsonify({'success': True, 'print_with_receipt': attachment.print_with_receipt})

@app.route('/api/products/<int:id>/attachments')
@login_required
def get_product_attachments(id):
    product = Product.query.get_or_404(id)
    return jsonify([a.to_dict() for a in product.attachments])

def receipt_datasheets(sale):
    """Attachments to offer on a receipt's print page, de-duplicated.

    Two line items for the same product must not print the same datasheet twice,
    and neither should two products that share one.
    """
    seen, sheets = set(), []
    for item in sale.line_items:
        if not item.product:
            continue
        for attachment in item.product.attachments:
            if not attachment.print_with_receipt or attachment.id in seen:
                continue
            seen.add(attachment.id)
            sheets.append({'product': item.product, 'attachment': attachment})
    return sheets

@app.route('/products/add', methods=['POST'])
@login_required
def add_product():
    fields, error = _parse_product_payload(request.json or {})
    if error:
        return jsonify({'success': False, 'error': error}), 400
    new_product = Product(**fields)
    db.session.add(new_product)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'error': f"A product with SKU '{fields['sku']}' already exists"}), 409
    return jsonify({'success': True, 'id': new_product.id})

@app.route('/products/edit/<int:id>', methods=['POST'])
@login_required
def edit_product(id):
    product = Product.query.get_or_404(id)
    fields, error = _parse_product_payload(request.json or {})
    if error:
        return jsonify({'success': False, 'error': error}), 400
    for key, value in fields.items():
        setattr(product, key, value)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'error': f"A product with SKU '{fields['sku']}' already exists"}), 409
    return jsonify({'success': True})

@app.route('/products/archive/<int:id>', methods=['POST'])
@login_required
def archive_product(id):
    product = Product.query.get_or_404(id)
    product.archived = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/products/delete/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    if LineItem.query.filter_by(product_id=id).first():
        return jsonify({
            'success': False,
            'error': 'This product is used on existing sales and cannot be deleted. Archive it instead.'
        }), 409
    db.session.delete(product)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/products')
@login_required
def get_products():
    products = Product.query.all()
    products_dict = [product.to_dict() for product in products]

    return jsonify(products_dict)

@app.route('/api/product/<int:id>')
@login_required
def get_product_api(id):
    product = Product.query.get_or_404(id)
    return jsonify(product.to_dict())

@app.route('/sales')
@login_required
def sales():
    sales = SalesReceipt.query.options(joinedload(SalesReceipt.customer)).all()
    sorted_sales = sorted(sales, key=lambda sale: sale.date, reverse=True)
    customers = Customer.query.all()
    sorted_customers = sorted(customers, key=lambda customer: customer.name, reverse=False)
    products = Product.query.filter_by(archived=False).all()
    sorted_products = sorted(products, key=lambda product: product.sku, reverse=False)
    company_info = CompanyInfo.get_info()

    return render_template('sales.html', sales=sorted_sales, customers=sorted_customers, products=sorted_products, company_info=company_info)

def _parse_money(value, field):
    """Parse a currency amount from the client ('$1,234.56', '', None)."""
    cleaned = str(value if value is not None else '').replace('$', '').replace(',', '').strip()
    try:
        amount = Decimal(cleaned or '0')
    except InvalidOperation:
        raise ValueError(f'{field} must be a number')
    if amount < 0:
        raise ValueError(f'{field} cannot be negative')
    return amount

def parse_sale_payload(data):
    """Validate a hand-entered sale into model-ready values. Raises ValueError.

    Shared by add_sale and edit_sale so the two cannot drift apart again. The
    edit route used to read `request.form` directly: it raised KeyError on any
    missing field, rejected '$1,234.56' because it called Decimal() rather than
    _parse_money, accepted a quantity of zero, and — the one that actually
    corrupts data — stored whatever `total` the client posted instead of
    computing it. The returned `total` is always line items + tax + shipping.

    `items` comes back as (product_id, quantity, price_each, total_price) tuples.
    """
    try:
        customer_id = int(data.get('customer_id') or 0)
    except (TypeError, ValueError):
        raise ValueError('Customer is invalid')
    if not customer_id:
        raise ValueError('Customer is required')

    if not data.get('date'):
        raise ValueError('Date is required')
    date_str = str(data['date']).strip()
    time_str = str(data.get('time') or '').strip()
    try:
        # Either a date plus a separate optional time (the add-sale modal), or a
        # single datetime-local value (the edit page). fromisoformat takes both
        # "HH:MM" and "HH:MM:SS".
        sale_date = datetime.fromisoformat(
            f'{date_str}T{time_str}' if time_str and 'T' not in date_str else date_str)
    except ValueError:
        raise ValueError('Invalid date/time')

    try:
        shipdate = (datetime.strptime(data['shipdate'], '%Y-%m-%d').date()
                    if data.get('shipdate') else None)
    except (TypeError, ValueError):
        raise ValueError('Invalid ship date')

    tax = _parse_money(data.get('tax'), 'Tax')
    shipping = _parse_money(data.get('shipping'), 'Shipping')

    if not data.get('line_items'):
        raise ValueError('At least one product is required')
    items = []
    subtotal = Decimal('0')
    for item in data['line_items']:
        if not item.get('product_id'):
            raise ValueError('Each line item needs a product selected')
        try:
            product_id = int(item['product_id'])
            quantity = int(item.get('quantity') or 0)
        except (TypeError, ValueError):
            raise ValueError('Product and quantity must be numbers')
        if quantity < 1:
            raise ValueError('Quantity must be at least 1')
        price_each = _parse_money(item.get('price_each'), 'Price')
        total_price = price_each * quantity
        subtotal += total_price
        items.append((product_id, quantity, price_each, total_price))

    return {
        'customer_id': customer_id,
        'date': sale_date,
        'shipdate': shipdate,
        'shipservice': data.get('shipservice') or None,
        'tracking': data.get('tracking') or None,
        'tax': tax,
        'shipping': shipping,
        'total': subtotal + tax + shipping,
        'customer_notes': data.get('customer_notes') or '',
        'internal_notes': data.get('internal_notes') or '',
        'external_order_number': data.get('external_order_number') or None,
        'items': items,
    }

def write_sale_line_items(sale, items):
    """Replace a receipt's line items with the parsed set from the operator."""
    for existing in sale.line_items:
        db.session.delete(existing)
    if sale.line_items:
        db.session.flush()
    for product_id, quantity, price_each, total_price in items:
        db.session.add(LineItem(
            receipt_id=sale.id,
            product_id=product_id,
            quantity=quantity,
            price_each=price_each,
            total_price=total_price
        ))

@app.route('/sales/add', methods=['POST'])
@login_required
def add_sale():
    try:
        fields = parse_sale_payload(request.json or {})
    except (ValueError, TypeError) as e:
        return jsonify({'success': False, 'error': str(e)}), 400

    items = fields.pop('items')
    # Marks the receipt as hand-entered so an import can never claim it
    new_sale = SalesReceipt(source='manual', **fields)
    db.session.add(new_sale)
    db.session.flush()

    # The receipt number is Sales Tracker's own identifier — the receipt's id
    new_sale.receipt_number = new_sale.id
    write_sale_line_items(new_sale, items)

    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error saving new sale: {e}")
        return jsonify({'success': False, 'error': 'Could not save the sale.'}), 500

    return jsonify({'success': True, 'id': new_sale.id})

@app.route('/sales/get/<int:id>')
@login_required
def get_sale(id):
    sale = SalesReceipt.query.options(joinedload(SalesReceipt.customer), joinedload(SalesReceipt.line_items)).get_or_404(id)
    return jsonify({
        'id': sale.id,
        'external_order_number': sale.external_order_number,
        'receipt_number': sale.receipt_number,
        'customer_id': sale.customer_id,
        'customer_name': sale.customer.name,
        'customer_email': sale.customer.email,
        'customer_phone': sale.customer.phone,
        'customer_company': sale.customer.company,
        'shipservice': sale.shipservice,
        'tracking': sale.tracking,
        'shipdate': sale.shipdate.strftime('%m-%d-%Y') if sale.shipdate else None,
        'date': sale.date.strftime('%m-%d-%Y'),
        'subtotal': float(sale.total - sale.tax - sale.shipping),
        'tax': float(sale.tax),
        'shipping': float(sale.shipping),
        'total': float(sale.total),
        'line_items': [{
            'product_id': item.product_id,
            'quantity': item.quantity,
            'price_each': float(item.price_each),
            'total_price': float(item.total_price)
        } for item in sale.line_items],
        'customer_notes': sale.customer_notes,
        'internal_notes': sale.internal_notes,
    })

@app.route('/sales/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_sale(id):
    sale = SalesReceipt.query.options(
        joinedload(SalesReceipt.customer),
        joinedload(SalesReceipt.line_items).joinedload(LineItem.product)
    ).get_or_404(id)
    
    if request.method == 'POST':
        try:
            fields = parse_sale_payload(request.json or {})
        except (ValueError, TypeError) as e:
            return jsonify({'success': False, 'error': str(e)}), 400

        items = fields.pop('items')
        for field, value in fields.items():
            setattr(sale, field, value)
        # `source` is deliberately left alone. Correcting a typo on an imported
        # receipt must not restamp it 'manual', and an adopted hand-entered sale
        # must keep the 'manual' that protects its figures from the next import.
        write_sale_line_items(sale, items)

        try:
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Error updating sale {id}: {e}")
            return jsonify({'success': False, 'error': 'Could not save the sale.'}), 500

        app.logger.info(f"Updated sale {id}")
        return jsonify({'success': True, 'id': sale.id,
                        'redirect': url_for('view_sale', id=sale.id)})

    # For GET requests, render the edit form
    customers = Customer.query.all()
    sorted_customers = sorted(customers, key=lambda customer: customer.name, reverse=False)
    products = Product.query.filter_by(archived=False).all()
    # Archived products already on this sale must stay selectable so its line items render
    archived_in_use = [item.product for item in sale.line_items if item.product and item.product.archived]
    sorted_products = sorted({*products, *archived_in_use}, key=lambda product: product.sku)
    company_info = CompanyInfo.get_info()

    return render_template('edit_sale.html', sale=sale, customers=sorted_customers, products=sorted_products, company_info=company_info)

@app.route('/sales/view/<int:id>')
@login_required
def view_sale(id):
    sale = SalesReceipt.query.options(
        joinedload(SalesReceipt.customer),
        joinedload(SalesReceipt.line_items).joinedload(LineItem.product)
    ).get_or_404(id)

    company_info = CompanyInfo.get_info()
    shipstation = ShipStationCredentials.query.first()

    return render_template('view_sale.html', sale=sale, company_info=company_info,
                           shipstation_enabled=bool(shipstation and shipstation.enabled))

@app.route('/sales/delete/<int:id>', methods=['POST'])
@login_required
def delete_sale(id):
    sale = SalesReceipt.query.get_or_404(id)

    try:
        # Reconciled bank transactions point at this receipt; unlink them first so
        # the delete cannot fail on the foreign key (kept: the transaction itself)
        unlinked = BankTransaction.query.filter_by(receipt_id=id).update(
            {BankTransaction.receipt_id: None}, synchronize_session=False)

        LineItem.query.filter_by(receipt_id=id).delete()
        db.session.delete(sale)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error deleting sale {id}: {e}")
        return jsonify({'success': False, 'error': 'Could not delete this sale.'}), 400

    message = f'Sale #{id} deleted.'
    if unlinked:
        message += f' Unlinked {unlinked} bank transaction(s).'
    return jsonify({'success': True, 'message': message})

@app.route('/sales/pending')
@login_required
def pending_orders():
    """Orders imported without buyer details, waiting for a customer to be named."""
    customers = Customer.query.order_by(Customer.name).all()
    return render_template('pending_orders.html',
                           customers=customers,
                           company_info=CompanyInfo.get_info())

@app.route('/api/pending_orders')
@login_required
def get_pending_orders():
    orders = PendingOrder.query.order_by(PendingOrder.order_date.desc()).all()
    return jsonify([order.to_dict() for order in orders])

@app.route('/api/pending_orders/count')
@login_required
def get_pending_order_count():
    return jsonify({'count': PendingOrder.query.count()})

@app.route('/sales/pending/<int:id>/complete', methods=['POST'])
@login_required
def complete_pending_order(id):
    """Turn a parked order into a real sales receipt against a named customer.

    Accepts either an existing customer_id, or a `customer` object to create one.
    The order's own figures (totals, tax, shipping, line items) are used as
    imported — only the buyer was ever missing.
    """
    pending = db.get_or_404(PendingOrder, id)
    data = request.json or {}

    try:
        order = json.loads(pending.payload or '{}')
    except ValueError:
        return jsonify({'success': False, 'error': 'This pending order is corrupted and '
                                                   'cannot be completed. Discard it and re-import.'}), 400

    if data.get('customer_id'):
        customer = db.session.get(Customer, int(data['customer_id']))
        if not customer:
            return jsonify({'success': False, 'error': 'That customer no longer exists.'}), 400
    else:
        fields, error = _parse_customer_payload(data.get('customer') or {})
        if error:
            return jsonify({'success': False, 'error': error}), 400
        customer = Customer(**fields)
        db.session.add(customer)
        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'success': False,
                            'error': f"A customer with the email {fields['email']} already "
                                     f"exists — pick them from the list instead."}), 409

    # Guard against two tabs completing the same order
    if find_existing_sale(pending.source, pending.external_order_id, None)[0]:
        db.session.rollback()
        return jsonify({'success': False,
                        'error': 'A sale for this order already exists.'}), 409

    sale = SalesReceipt(customer_id=customer.id)
    db.session.add(sale)

    # Money and dates come back off the payload as strings via json_safe
    order['order_total'] = Decimal(str(order.get('order_total', '0')))
    order['tax_amount'] = Decimal(str(order.get('tax_amount', '0')))
    order['shipping_amount'] = Decimal(str(order.get('shipping_amount', '0')))
    if order.get('order_date'):
        order['order_date'] = datetime.fromisoformat(order['order_date'])
    if order.get('shipdate'):
        order['shipdate'] = date.fromisoformat(order['shipdate'])

    apply_order_to_sale(sale, order, pending.source, customer, is_new=True)
    db.session.flush()
    sale.receipt_number = str(sale.id)
    replace_line_items(sale, order.get('items', []))

    db.session.delete(pending)
    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Could not complete pending order {id}: {e}")
        return jsonify({'success': False, 'error': 'Could not save the sale.'}), 500

    app.logger.info(f"Completed pending {pending.source} order {pending.external_order_number} "
                    f"as sale {sale.id}")
    return jsonify({'success': True, 'id': sale.id,
                    'message': f'Sale #{sale.id} created for {customer.name}.'})

@app.route('/sales/pending/<int:id>/delete', methods=['POST'])
@login_required
def delete_pending_order(id):
    pending = db.get_or_404(PendingOrder, id)
    label = pending.external_order_number or pending.external_order_id
    db.session.delete(pending)
    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Could not discard pending order {id}: {e}")
        return jsonify({'success': False, 'error': 'Could not discard this order.'}), 500
    return jsonify({'success': True, 'message': f'Discarded pending order {label}.'})

@app.route('/sales/print/<int:id>')
@login_required
def print_sale(id):
    sale = SalesReceipt.query.options(
        joinedload(SalesReceipt.customer),
        joinedload(SalesReceipt.line_items)
            .joinedload(LineItem.product)
            .joinedload(Product.attachments)
    ).get_or_404(id)
    company_info = CompanyInfo.get_info()

    return render_template('print_sale.html', sale=sale, company_info=company_info,
                           datasheets=receipt_datasheets(sale))

@app.route('/api/sales')
@login_required
def get_SalesReceipt():
    """All receipts, newest first. Backs the sales grid and banking.html."""
    sales = (SalesReceipt.query
             .options(joinedload(SalesReceipt.customer),
                      joinedload(SalesReceipt.line_items).joinedload(LineItem.product))
             .order_by(SalesReceipt.date.desc()).all())
    return jsonify([sale.to_dict() for sale in sales])

def require_integration(model, label):
    """Return (credentials, None) when an integration is usable, else (None, response)."""
    credentials = model.query.first()
    if not credentials:
        return None, (jsonify({'error': f'{label} credentials have not been saved yet. '
                                        f'Add them on the Management page.'}), 400)
    if not credentials.enabled:
        return None, (jsonify({'error': f'{label} integration is turned off. '
                                        f'Enable it on the Management page.'}), 400)
    return credentials, None

def integration_error_detail(response):
    """Pull the server's own explanation out of an error body, if it gave one.

    Worth the trouble because a 403 usually is not what it looks like: Shopify
    answers with "[API] This action requires merchant approval for read_orders
    scope", which is a scope problem, not a credential problem. Repeating our own
    guess about the API key instead sends the operator to the wrong screen.
    """
    try:
        payload = response.json()
    except ValueError:
        return ''
    if not isinstance(payload, dict):
        return ''
    for key in ('errors', 'error_description', 'error', 'message'):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        # WooCommerce and Shopify both also use {"errors": {"field": ["reason"]}}
        if isinstance(value, dict) and value:
            return '; '.join(
                f"{k}: {', '.join(str(v) for v in vs) if isinstance(vs, list) else vs}"
                for k, vs in value.items())
        if isinstance(value, list) and value:
            return '; '.join(str(v) for v in value)
    return ''

def integration_request(method, url, label, **kwargs):
    """Call an integration's HTTP API and translate failures into readable errors.

    Auth failures in particular used to surface as a generic 500; the operator
    needs to know the saved credentials are the problem.
    """
    kwargs.setdefault('timeout', 60)
    try:
        response = requests.request(method, url, **kwargs)
    except requests.RequestException as e:
        app.logger.error(f"{label} request to {url} failed: {e}")
        raise IntegrationError(f'Could not reach {label}. Check the network connection.')

    if response.status_code in (401, 403):
        detail = integration_error_detail(response)
        app.logger.error(f"{label} refused the request ({response.status_code}) for {url}: "
                         f"{response.text[:500]}")
        if detail:
            raise IntegrationError(f'{label} refused the request ({response.status_code}): {detail}')
        raise IntegrationError(f'{label} rejected the saved credentials. '
                               f'Check the API key/secret on the Management page.')
    if response.status_code == 429:
        raise IntegrationError(f'{label} is rate limiting us. Try a smaller date range.')
    if not response.ok:
        app.logger.error(f"{label} returned {response.status_code} for {url}: {response.text[:500]}")
        raise IntegrationError(f'{label} returned an error ({response.status_code}).')
    return response

class IntegrationError(Exception):
    """A user-facing failure talking to an external order source."""

def json_safe(value):
    """Serialise Decimals, dates and datetimes for storage in a JSON column."""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    raise TypeError(f'Not JSON serialisable: {type(value)!r}')

def upsert_pending_order(order, source):
    """Park an order whose buyer details the platform withheld.

    No SalesReceipt and no customer record are created. A half-identified sale
    would be worse than none: `get_state_info` cannot classify an address with no
    city or ZIP, so it would silently land in the 'Unknown' bucket and understate
    the WA totals with nothing to show that it had happened.

    Re-imports update the parked row in place rather than stacking duplicates.
    """
    external_order_id = str(order.get('external_order_id') or '')
    pending = PendingOrder.query.filter_by(
        source=source, external_order_id=external_order_id).first()
    if pending is None:
        pending = PendingOrder(source=source, external_order_id=external_order_id)
        db.session.add(pending)
        created = True
    else:
        created = False

    pending.external_order_number = str(order.get('external_order_number') or '')
    pending.order_date = order.get('order_date')
    pending.total = float(order.get('order_total') or 0)
    pending.tax = float(order.get('tax_amount') or 0)
    pending.shipping = float(order.get('shipping_amount') or 0)
    pending.shipservice = order.get('shipservice')
    pending.tracking = order.get('tracking')
    pending.shipdate = order.get('shipdate')
    pending.customer_notes = order.get('customer_notes') or ''
    pending.internal_notes = order.get('internal_notes') or ''
    # Everything needed to build the receipt later, including whatever partial
    # location hints the platform did share
    pending.payload = json.dumps(order, default=json_safe)
    db.session.flush()
    return created

# How far a hand-entered date may sit from the platform's before the two stop
# being plausibly the same order. A day absorbs a timezone-edge or a date typed
# from a UTC-displayed admin screen without letting unrelated orders match.
UNCLAIMED_MATCH_WINDOW = timedelta(days=1)

def normalise_order_number(value):
    """Compare order numbers the way a person would: '#1797', '1797 ' are one."""
    return str(value or '').strip().lstrip('#').strip()

def _order_numbers_agree(left, right):
    left, right = normalise_order_number(left), normalise_order_number(right)
    return bool(left) and left == right

def find_unclaimed_sale(external_order_number, order_date):
    """Find a hand-entered receipt that is plainly this same order, or None.

    An operator who enters a store order themselves puts its order number in
    external_order_number and leaves external_order_id empty, so the reliable key
    below cannot see it and the import would write a second receipt for a sale
    already on the books — then ask for a customer it already has.

    The order number alone is not enough to match on: it is not unique in the
    live data, and other platforms number orders in the same ranges. Requiring
    the dates to agree too makes a collision implausible — two different orders
    sharing a number *and* a day. Precision is what matters here: a missed match
    only produces the duplicate we already get today, which is visible and easy
    to delete, whereas a wrong match silently welds two unrelated sales together.

    Only unclaimed receipts qualify. Anything already carrying an
    external_order_id belongs to an importer and is found by the reliable key.
    """
    if not order_date:
        return None
    number = normalise_order_number(external_order_number)
    if not number:
        return None

    candidates = SalesReceipt.query.filter(
        SalesReceipt.external_order_id.is_(None),
        db.or_(SalesReceipt.source.is_(None), SalesReceipt.source == 'manual'),
        # Live rows carry stray whitespace, and stores differ on the '#' prefix
        db.or_(func.trim(SalesReceipt.external_order_number) == number,
               func.trim(SalesReceipt.external_order_number) == f'#{number}'),
    ).all()

    for sale in candidates:
        if sale.date and abs(sale.date - order_date) <= UNCLAIMED_MATCH_WINDOW:
            return sale
    return None

def find_existing_sale(source, external_order_id, external_order_number, order_date=None):
    """Find the receipt an imported order belongs to. Returns (sale, adopted).

    Matching is on (source, external_order_id) — the only pair guaranteed unique
    per platform. The platform's order number alone is not: imported rows hold the
    number while hand-entered rows hold their own receipt id, and the live data
    already contains duplicates. The legacy fallback is kept only for rows
    imported before `source` existed, and those rows get stamped on first match so
    the reliable key applies from then on.

    `adopted` means the receipt was typed in by hand and merely recognised as this
    order, rather than written by an importer. That has to survive every later
    import, not just the one that spotted it, so an adopted receipt keeps
    source='manual' and is re-identified by tier 2 below on each subsequent run.
    Stamping it 'shopify' would make the next import treat it as its own and
    overwrite the operator's figures — the exact cleanup this matching avoids.
    """
    if external_order_id:
        sale = SalesReceipt.query.filter_by(
            source=source, external_order_id=str(external_order_id)).first()
        if sale:
            return sale, False

        # A hand-entered receipt adopted by an earlier run. The order number must
        # agree as well, so an id from another platform that happens to be
        # numerically equal cannot claim it.
        sale = SalesReceipt.query.filter(
            SalesReceipt.source == 'manual',
            SalesReceipt.external_order_id == str(external_order_id),
        ).first()
        if sale and _order_numbers_agree(sale.external_order_number, external_order_number):
            return sale, True

    if external_order_number:
        # Legacy rows stored the marketplace number in what is now
        # receipt_number; that is the only reason to look there.
        sale = SalesReceipt.query.filter(
            SalesReceipt.source.is_(None),
            SalesReceipt.receipt_number == str(external_order_number)
        ).first()
        if sale:
            return sale, False

    sale = find_unclaimed_sale(external_order_number, order_date)
    return (sale, True) if sale else (None, False)

def apply_order_to_sale(sale, order, source, customer, is_new, adopted=False):
    """Copy a processed order's header fields onto a receipt.

    Three identifiers, three distinct jobs — they had drifted into each other:
      * receipt_number        Sales Tracker's own receipt number. Set to the
                              receipt's id once it has one (see
                              import_processed_orders), matching what add_sale
                              does. Never the marketplace's number.
      * external_order_number the marketplace/platform order number, shown as
                              "Order #". Display only.
      * external_order_id     the platform's internal order id, used solely as
                              the duplicate-detection key.

    Deliberately excluded on re-import:
      * customer_id — reassigning it would undo a manual customer merge
      * line items  — they may have been corrected by hand; only new receipts
                      get them built (see import_processed_orders)

    `adopted` means this receipt was entered by hand and has been recognised as
    the platform's order (see find_unclaimed_sale). We link it, so it can never be
    imported twice, but leave the operator's own figures exactly as typed: they
    may already account for a discount or a refund the API still reports at face
    value, and overwriting them would be the silent cleanup job this matching
    exists to avoid. Blanks are still filled in. `source` deliberately stays
    'manual' — it is what marks the receipt as the operator's on every later run.
    """
    if is_new:
        sale.customer_id = customer.id
    if adopted:
        # Rows predating the column have source NULL. Naming them for what they
        # are is what lets the next run recognise them as the operator's instead
        # of importing the order a second time.
        sale.source = sale.source or 'manual'
    else:
        sale.source = source
    sale.external_order_id = str(order['external_order_id']) if order.get('external_order_id') else None
    if order.get('external_order_number'):
        sale.external_order_number = str(order['external_order_number'])

    if not adopted:
        if order.get('order_date'):
            sale.date = order['order_date']
        sale.total = order['order_total']
        sale.tax = order['tax_amount']
        sale.shipping = order['shipping_amount']

    for field in ('shipservice', 'tracking', 'shipdate'):
        if order.get(field) is None:
            continue
        if adopted and getattr(sale, field):
            continue  # what the operator recorded wins
        setattr(sale, field, order[field])

    if adopted:
        # Say what actually happened; 'Imported from Shopify' would be a lie on a
        # receipt someone typed, and the operator needs to see why it now carries
        # an order id it did not have yesterday.
        order = dict(order, internal_notes=(
            f"Matched to {source} order {order.get('external_order_number')} on import. "
            f"Totals left as entered."))

    # Notes are appended rather than replaced so hand-written context survives
    for field in ('customer_notes', 'internal_notes'):
        incoming = (order.get(field) or '').strip()
        if not incoming:
            continue
        existing = (getattr(sale, field) or '').strip()
        if not existing:
            setattr(sale, field, incoming)
        elif incoming not in existing:
            setattr(sale, field, f"{existing}\n{incoming}")

class ImportResult(namedtuple('ImportResult', 'created updated adopted errors pending')):
    """What one import run did. `adopted` counts sales that already existed by
    hand and were linked to the platform instead of being duplicated."""
    __slots__ = ()

def discard_pending_order(source, external_order_id):
    """Drop a parked order once a receipt exists for it.

    An order can be parked for missing buyer details and then entered by hand
    before the next import. Without this the queue keeps asking for a sale that
    is already on the books.
    """
    if not external_order_id:
        return
    stale = PendingOrder.query.filter_by(
        source=source, external_order_id=str(external_order_id)).first()
    if stale:
        db.session.delete(stale)

def import_processed_orders(processed_orders, source, enrich=None):
    """Persist processed orders, one savepoint per order. Returns an ImportResult.

    Everything runs on db.session. The old code wrote sales on a raw Session()
    while get_or_create_customer/_product wrote db.session and never committed it,
    so an imported sale could commit while the customer row it pointed at was
    rolled back. With foreign keys now enforced that would be a hard failure
    rather than a silent orphan.

    A failing order rolls back only its own savepoint and is reported in errors[];
    the rest of the batch still commits. Previously one bad order called
    session.rollback() and discarded everything processed before it.
    """
    created = updated = adopted_count = pending = 0
    errors = []

    for order in processed_orders:
        label = order.get('external_order_number') or order.get('external_order_id') or 'unknown'
        try:
            with db.session.begin_nested():
                if enrich:
                    enrich(order)

                existing, adopted = find_existing_sale(
                    source, order.get('external_order_id'),
                    order.get('external_order_number'), order.get('order_date'))

                # No buyer details and no receipt yet — park it for manual entry
                # instead of inventing a customer. If a receipt already exists,
                # the details were supplied once and the header still updates.
                if order.get('customer_data_unavailable') and existing is None:
                    if upsert_pending_order(order, source):
                        pending += 1
                    continue

                if existing is not None:
                    discard_pending_order(source, order.get('external_order_id'))

                sale = existing
                is_new = sale is None
                if is_new:
                    # Resolve a customer only when one is actually needed. On an
                    # existing receipt apply_order_to_sale never reassigns
                    # customer_id, so doing this unconditionally just stranded a
                    # new Customer row — every time, for orders with no email,
                    # since those get a fresh placeholder address each run.
                    customer = get_or_create_customer(order['customer'])
                    sale = SalesReceipt(customer_id=customer.id)
                    db.session.add(sale)
                else:
                    customer = sale.customer

                apply_order_to_sale(sale, order, source, customer, is_new, adopted)
                db.session.flush()

                if is_new:
                    # The receipt number is Sales Tracker's own identifier, not a
                    # second copy of the marketplace order number. add_sale uses
                    # the same rule for hand-entered sales.
                    sale.receipt_number = str(sale.id)
                    replace_line_items(sale, order['items'])
                    created += 1
                elif adopted:
                    app.logger.info(
                        f"Linked {source} order {label} to hand-entered receipt "
                        f"{sale.receipt_number} instead of creating a duplicate")
                    adopted_count += 1
                else:
                    updated += 1
        except Exception as e:
            message = f"Order {label}: {e}"
            app.logger.error(f"Error importing {source} order {label}: {e}", exc_info=True)
            errors.append(message)
            continue

    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Could not commit {source} import: {e}")
        raise IntegrationError('Import could not be saved to the database.')

    return ImportResult(created, updated, adopted_count, errors, pending)

def import_response(source_label, result):
    message = (f'{source_label} import finished. '
               f'Created {result.created} new orders. Updated {result.updated} existing orders.')
    if result.adopted:
        message += (f' {result.adopted} order(s) you had already entered by hand were '
                    f'matched to {source_label} rather than duplicated.')
    if result.pending:
        message += (f' {result.pending} order(s) are awaiting customer details — '
                    f'the store withheld them. Open Pending Orders to complete them.')
    if result.errors:
        message += f' {len(result.errors)} order(s) could not be imported.'
    status = 200 if not (result.errors or result.pending) else 207
    return jsonify({'message': message, 'errors': result.errors,
                    'adopted': result.adopted, 'pending': result.pending}), status

def shipstation_order_id_for(sale):
    """Best available ShipStation orderId for a receipt.

    New imports store it in external_order_id. Rows imported by older versions
    used the ShipStation orderId as the receipt's own primary key, which is why
    `id` is the fallback — external_order_number holds the marketplace order
    number on those rows, not the orderId.
    """
    return sale.external_order_id or str(sale.id)

def shipstation_get_shipment(credentials, order_id):
    """Fetch an order's shipments. Raises IntegrationError; never returns a Response."""
    response = integration_request(
        'GET', 'https://ssapi.shipstation.com/shipments', 'ShipStation',
        params={'orderId': order_id, 'includeShipmentItems': True},
        auth=(credentials.api_key, credentials.api_secret))
    return response.json()

def shipment_fields(shipment_payload):
    """Pull carrier/tracking/ship date out of a ShipStation shipments response."""
    shipments = (shipment_payload or {}).get('shipments') or []
    if not shipments:
        return {}
    shipment = shipments[0]
    fields = {}
    service_code = shipment.get('serviceCode') or ''
    if service_code:
        # "usps_priority_mail" -> "USPS"
        fields['shipservice'] = service_code.split('_')[0].upper()
    if shipment.get('trackingNumber'):
        fields['tracking'] = shipment['trackingNumber']
    if shipment.get('shipDate'):
        try:
            fields['shipdate'] = datetime.strptime(shipment['shipDate'], '%Y-%m-%d').date()
        except ValueError:
            app.logger.warning(f"Unparseable ShipStation shipDate: {shipment['shipDate']!r}")
    return fields

def shipstation_fetch_orders(credentials, start_date, end_date):
    """Page ShipStation's shipped orders over a date range."""
    all_orders = []
    page = 1
    while True:
        response = integration_request(
            'GET', 'https://ssapi.shipstation.com/orders', 'ShipStation',
            params={
                'orderDateStart': start_date.isoformat(),
                'orderDateEnd': end_date.isoformat(),
                'orderStatus': 'shipped',
                'pageSize': 500,  # Maximum allowed by ShipStation
                'page': page,
            },
            auth=(credentials.api_key, credentials.api_secret))
        data = response.json()
        all_orders.extend(data.get('orders', []))
        if page >= data.get('pages', 1):
            break
        page += 1
    return all_orders

def shipstation_enrich(credentials):
    """Per-order shipment lookup, run inside that order's savepoint so a failure
    here only skips this one order."""
    def attach_shipment(order):
        order.update(shipment_fields(
            shipstation_get_shipment(credentials, order['external_order_id'])))
    return attach_shipment

@app.route('/shipstation/fetch_orders', methods=['POST'])
@login_required
@retry_on_db_lock()
def fetch_shipstation_orders():
    return run_integration_import('shipstation')

@app.route('/shipstation/fetch_shipment/<int:id>', methods=['POST'])
@login_required
def fetch_shipstation_shipment(id):
    credentials, error = require_integration(ShipStationCredentials, 'ShipStation')
    if error:
        return error
    try:
        return jsonify(shipstation_get_shipment(credentials, id)), 200
    except IntegrationError as e:
        return jsonify({'error': str(e)}), 502

@app.route('/shipstation/update_shipment/<int:id>', methods=['POST'])
@login_required
def update_shipment(id):
    """Refresh one receipt's carrier/tracking/ship date and notes from ShipStation."""
    credentials, error = require_integration(ShipStationCredentials, 'ShipStation')
    if error:
        return error

    sale = db.get_or_404(SalesReceipt, id)
    order_id = shipstation_order_id_for(sale)

    try:
        fields = shipment_fields(shipstation_get_shipment(credentials, order_id))
        if not fields:
            return jsonify({'error': f'ShipStation has no shipment for order {order_id}.'}), 404
        notes = shipstation_order_notes(credentials, order_id)
    except IntegrationError as e:
        return jsonify({'error': str(e)}), 502

    for field, value in fields.items():
        setattr(sale, field, value)
    apply_incoming_notes(sale, notes)

    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error saving ShipStation update for sale {id}: {e}")
        return jsonify({'error': 'Could not save the update.'}), 500

    app.logger.info(f"Updated sale {id} from ShipStation order {order_id}")
    return jsonify({'success': True, 'message': f'Sale #{id} updated from ShipStation.'})

def shipstation_order_notes(credentials, order_id):
    """Fetch customer/internal notes for a ShipStation order."""
    response = integration_request(
        'GET', f'https://ssapi.shipstation.com/orders/{order_id}', 'ShipStation',
        auth=(credentials.api_key, credentials.api_secret))
    order = response.json()
    return {
        'customer_notes': order.get('customerNotes') or '',
        'internal_notes': order.get('internalNotes') or '',
    }

def apply_incoming_notes(sale, notes):
    """Append notes that aren't already present, leaving hand-written text intact."""
    for field in ('customer_notes', 'internal_notes'):
        incoming = (notes.get(field) or '').strip()
        if not incoming:
            continue
        existing = (getattr(sale, field) or '').strip()
        if not existing:
            setattr(sale, field, incoming)
        elif incoming not in existing:
            setattr(sale, field, f"{existing}\n{incoming}")

def shippo_fetch_orders(credentials, start_date, end_date):
    """Page Shippo's shipped orders over a date range."""
    headers = {
        'Authorization': f'ShippoToken {credentials.api_key}',
        'Content-Type': 'application/json'
    }
    all_orders = []
    page = 1
    while True:
        response = integration_request(
            'GET', 'https://api.goshippo.com/orders', 'Shippo',
            params={
                'results': 25,  # Shippo's page size
                'page': page,
                'start_date': f'{start_date.isoformat()}T00:00:00',
                'end_date': f'{end_date.isoformat()}T23:59:59',
                'order_status[]': 'SHIPPED',
            },
            headers=headers)
        data = response.json()
        # Bodies are not logged: Shippo order payloads carry customer names,
        # addresses and phone numbers, which do not belong in an INFO log
        app.logger.info(f"Shippo page {page}: {len(data.get('results', []))} order(s)")
        all_orders.extend(data.get('results', []))
        if not data.get('next'):
            break
        page += 1
    return all_orders

@app.route('/shippo/fetch_orders', methods=['POST'])
@login_required
@retry_on_db_lock()
def fetch_shippo_orders():
    return run_integration_import('shippo')

@app.route('/woocommerce/fetch_orders', methods=['POST'])
@login_required
def fetch_woocommerce_orders():
    """Placeholder so enabling WooCommerce gives a clear answer instead of a 404.

    The importer itself is still to be written (roadmap E5).
    """
    credentials, error = require_integration(WooCommerceCredentials, 'WooCommerce')
    if error:
        return error
    return jsonify({
        'error': 'The WooCommerce importer has not been built yet. '
                 'Credentials are saved and the connection is ready for it.'
    }), 501

# ---------------------------------------------------------------------------
# Shopify
#
# Two ways in, sharing one import path:
#   * POST /shopify/fetch_orders — operator picks a date range, we page the Admin
#     REST API. Works from a LAN-only box, and is the backfill/repair tool.
#   * POST /shopify/webhook      — Shopify pushes orders/create|updated|fulfilled
#     as they happen. Needs a public HTTPS URL and verifies every request's HMAC.
#
# Both land in import_processed_orders keyed on (source='shopify', order id), so a
# webhook and a later manual fetch of the same order update one receipt rather
# than creating two. See integrations-shopify.md for setup and trade-offs.
# ---------------------------------------------------------------------------

# Shopify supports each dated version for 12 months; bump this periodically.
SHOPIFY_API_VERSION = os.environ.get('SHOPIFY_API_VERSION', '2026-01')

# Environment variables that stand in for stored credentials, in priority order.
# Set any of these (typically via .env) and it wins over the database value, so a
# development machine never has to paste secrets into the Management page.
SHOPIFY_ENV_FIELDS = {
    'shop_domain': ('SHOPIFY_SHOP_DOMAIN', 'SHOPIFY_STORE_DOMAIN'),
    'api_key': ('SHOPIFY_ADMIN_API_TOKEN', 'SHOPIFY_ACCESS_TOKEN'),
    'api_secret': ('SHOPIFY_API_SECRET',),
    'client_id': ('SHOPIFY_CLIENT_ID',),
    'client_secret': ('SHOPIFY_CLIENT_SECRET', 'SHOPIFY_SECRET'),
}

def shopify_env_value(field):
    for name in SHOPIFY_ENV_FIELDS.get(field, ()):
        value = (os.environ.get(name) or '').strip()
        if value:
            return value
    return ''

def shopify_setting(credentials, field):
    """Resolve one credential field: environment first, then the database."""
    return shopify_env_value(field) or (getattr(credentials, field, '') or '').strip()

def shopify_auth_mode(credentials):
    """Which authentication route to use.

    An explicit choice in the database wins. Otherwise infer it: a client id and
    secret mean the Dev Dashboard route, a bare access token means the legacy
    custom app. This keeps a .env that only defines SHOPIFY_CLIENT_ID/SECRET
    working without anyone having to pick a mode in the UI first.
    """
    stored = (credentials.auth_mode or '').strip()
    if stored in ('token', 'client_credentials'):
        # An env-supplied client id still overrides a stale stored 'token'
        if stored == 'token' and shopify_env_value('client_id') and not shopify_env_value('api_key'):
            return 'client_credentials'
        return stored
    if shopify_setting(credentials, 'client_id') and shopify_setting(credentials, 'client_secret'):
        return 'client_credentials'
    return 'token'

def shopify_shop_domain(credentials):
    """Normalise whatever was pasted into the field to a bare host."""
    domain = shopify_setting(credentials, 'shop_domain')
    domain = domain.replace('https://', '').replace('http://', '').strip('/')
    # Tolerate a full storefront URL with a path
    return domain.split('/')[0]

def shopify_webhook_secret(credentials):
    """The secret Shopify signs webhooks with, which differs per auth route.

    Legacy custom apps sign with the app's API secret key; Dev Dashboard apps
    sign with the client secret. Fall back to whichever is configured so a store
    that has both set does not silently reject valid deliveries.
    """
    if shopify_auth_mode(credentials) == 'client_credentials':
        return shopify_setting(credentials, 'client_secret') or shopify_setting(credentials, 'api_secret')
    return shopify_setting(credentials, 'api_secret') or shopify_setting(credentials, 'client_secret')

# Refresh a little early so a token cannot expire mid-import
SHOPIFY_TOKEN_SAFETY_MARGIN = timedelta(minutes=5)

def shopify_request_access_token(credentials):
    """Exchange client id + secret for a 24-hour Admin API access token.

    POST https://{shop}/admin/oauth/access_token
        grant_type=client_credentials&client_id=…&client_secret=…
      -> {"access_token": "shpat_…", "scope": "…", "expires_in": 86399}

    The result is cached on the credentials row, so restarts and concurrent
    worker threads reuse one token instead of requesting a new one per fetch.
    """
    domain = shopify_shop_domain(credentials)
    client_id = shopify_setting(credentials, 'client_id')
    client_secret = shopify_setting(credentials, 'client_secret')
    if not (client_id and client_secret):
        raise IntegrationError('Shopify client ID and client secret are required for '
                               'the Dev Dashboard authentication route.')

    response = integration_request(
        'POST', f'https://{domain}/admin/oauth/access_token', 'Shopify',
        data={
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'})

    payload = response.json()
    token = payload.get('access_token')
    if not token:
        raise IntegrationError('Shopify did not return an access token. '
                               'Check the client ID and secret.')

    # Shopify issues a token even when the app was released with no scopes
    # approved, and every orders request then 403s with nothing here to explain
    # it. Fail now, with the fix, rather than one confusing layer later. Nothing
    # is cached: a scopeless token is not worth reusing for 24 hours.
    granted = {s.strip() for s in (payload.get('scope') or '').split(',') if s.strip()}
    if not granted & {'read_orders', 'read_all_orders'}:
        raise IntegrationError(
            'Shopify issued a token with '
            + (f"only these scopes: {', '.join(sorted(granted))}" if granted
               else 'no access scopes at all')
            + '. Orders need read_orders. In the Shopify Dev Dashboard, add '
              'read_orders, read_customers, read_fulfillments and read_products to '
              'the app configuration, release that version, then install the app on '
              'the store so the scopes are approved.')

    expires_in = int(payload.get('expires_in') or 86400)
    credentials.access_token = token
    credentials.access_token_expires_at = datetime.now() + timedelta(seconds=expires_in)
    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        # A token we could not cache is still a usable token for this request
        app.logger.warning(f"Could not cache the Shopify access token: {e}")

    app.logger.info(f"Obtained a Shopify access token, valid for {expires_in}s, "
                    f"scopes: {', '.join(sorted(granted))}")
    return token

def shopify_access_token(credentials):
    """A usable Admin API token for whichever auth route is configured."""
    if shopify_auth_mode(credentials) == 'token':
        token = shopify_setting(credentials, 'api_key')
        if not token:
            raise IntegrationError('No Shopify Admin API access token is saved. '
                                   'Add one on the Management page.')
        return token

    cached = (credentials.access_token or '').strip()
    expires_at = credentials.access_token_expires_at
    if cached and expires_at and datetime.now() + SHOPIFY_TOKEN_SAFETY_MARGIN < expires_at:
        return cached
    return shopify_request_access_token(credentials)

def shopify_api_url(credentials, path):
    return f"https://{shopify_shop_domain(credentials)}/admin/api/{SHOPIFY_API_VERSION}/{path}"

def shopify_next_page_url(link_header):
    """Shopify pages with a Link header, not page numbers.

    Link: <https://…?page_info=abc>; rel="next"
    The page_info cursor already encodes the filters, so the follow-up request
    must send that URL as-is with no extra query parameters.
    """
    for part in (link_header or '').split(','):
        segments = part.split(';')
        if len(segments) < 2:
            continue
        if 'rel="next"' in segments[1].replace(' ', '').replace("'", '"'):
            return segments[0].strip().strip('<>')
    return None

def shopify_fetch_order_pages(credentials, start_date, end_date, max_pages=100):
    headers = {
        'X-Shopify-Access-Token': shopify_access_token(credentials),
        'Content-Type': 'application/json',
    }
    url = shopify_api_url(credentials, 'orders.json')
    params = {
        'status': 'any',
        'created_at_min': f'{start_date}T00:00:00',
        'created_at_max': f'{end_date}T23:59:59',
        'limit': 250,  # Shopify's maximum page size
    }

    orders = []
    for page in range(max_pages):
        response = integration_request('GET', url, 'Shopify', params=params, headers=headers)
        batch = response.json().get('orders', [])
        orders.extend(batch)
        app.logger.info(f"Shopify page {page + 1}: {len(batch)} order(s)")

        url = shopify_next_page_url(response.headers.get('Link'))
        if not url:
            break
        params = None
    else:
        app.logger.warning(f"Stopped paging Shopify orders at {max_pages} pages")

    return orders

def parse_shopify_datetime(value):
    """Parse Shopify's ISO 8601 timestamps into naive local datetimes."""
    if not value:
        return None
    text = value.strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        return to_local_naive(datetime.fromisoformat(text))
    except ValueError:
        app.logger.warning(f"Unparseable Shopify timestamp: {value!r}")
        return None

def shopify_shipping_amount(order):
    """Total shipping charged, in the shop's own currency."""
    shipping_set = (order.get('total_shipping_price_set') or {}).get('shop_money') or {}
    if shipping_set.get('amount') is not None:
        return Decimal(str(shipping_set['amount']))
    # Older payloads only carry the per-line breakdown
    return sum((Decimal(str(line.get('price', '0')))
                for line in order.get('shipping_lines') or []), Decimal('0'))

def process_shopify_data(shopify_orders):
    """Translate Shopify order payloads into the shape import_processed_orders wants."""
    processed_orders = []

    for order in shopify_orders:
        try:
            if order.get('test'):
                app.logger.info(f"Skipping Shopify test order {order.get('name')}")
                continue
            if order.get('cancelled_at'):
                app.logger.info(f"Skipping cancelled Shopify order {order.get('name')}")
                continue

            address = order.get('shipping_address') or order.get('billing_address') or {}
            customer = order.get('customer') or {}
            name = address.get('name') or ' '.join(
                filter(None, [address.get('first_name'), address.get('last_name')])) or \
                ' '.join(filter(None, [customer.get('first_name'), customer.get('last_name')]))

            customer_data = {
                'name': name or 'Unknown',
                'email': order.get('email') or customer.get('email') or '',
                'company': address.get('company') or '',
                'street1': address.get('address1') or '',
                'street2': address.get('address2') or '',
                'street3': '',
                'city': address.get('city') or '',
                # province_code is the USPS abbreviation get_state_info expects
                'state': address.get('province_code') or address.get('province') or '',
                'postal_code': address.get('zip') or '',
                'country': address.get('country_code') or '',
                'phone': address.get('phone') or customer.get('phone') or '',
            }

            # Name, email, phone and address are all Shopify "Level 2" protected
            # customer data. For an admin-created custom app that access depends
            # on the store's plan, so on anything below Advanced they come back
            # null and there is nothing here to identify the buyer with. Import
            # the order anyway and flag it — order totals and line items are
            # still worth having.
            customer_data_unavailable = not any([
                customer_data['email'],
                name,
                customer_data['street1'],
                customer_data['postal_code'],
            ])

            order_date = parse_shopify_datetime(order.get('created_at')) or datetime.now()

            # Most recent fulfillment carries the carrier and tracking we display
            shipservice = tracking = shipdate = None
            fulfillments = order.get('fulfillments') or []
            if fulfillments:
                fulfillment = fulfillments[-1]
                tracking = fulfillment.get('tracking_number') or None
                carrier = (fulfillment.get('tracking_company') or '').strip()
                if carrier:
                    shipservice = carrier.split()[0].upper()
                fulfilled_at = parse_shopify_datetime(fulfillment.get('created_at'))
                shipdate = fulfilled_at.date() if fulfilled_at else None

            items = []
            for line in order.get('line_items') or []:
                quantity = int(line.get('quantity') or 0)
                if quantity < 1:
                    continue
                items.append({
                    'sku': line.get('sku') or line.get('title') or 'Unknown SKU',
                    'name': line.get('title') or 'Unknown Item',
                    'quantity': quantity,
                    'unit_price': Decimal(str(line.get('price', '0'))),
                })

            internal_notes = 'Imported from Shopify'
            if customer_data_unavailable:
                internal_notes += (' — Shopify withheld the customer details for this '
                                   'order (store plan does not grant protected customer '
                                   'data). Enter the customer by hand.')

            processed_orders.append({
                'external_order_id': str(order['id']),
                # "#1001" — the order number the merchant and buyer both see
                'external_order_number': order.get('name') or str(order.get('order_number') or order['id']),
                'order_date': order_date,
                'shipservice': shipservice,
                'tracking': tracking,
                'shipdate': shipdate,
                'customer': customer_data,
                'customer_data_unavailable': customer_data_unavailable,
                'items': items,
                'order_total': Decimal(str(order.get('total_price', '0'))),
                'tax_amount': Decimal(str(order.get('total_tax', '0'))),
                'shipping_amount': shopify_shipping_amount(order),
                'customer_notes': order.get('note') or '',
                'internal_notes': internal_notes,
            })
        except Exception as e:
            app.logger.error(
                f"Skipping malformed Shopify order {order.get('name', order.get('id', 'Unknown'))}: {e}")
            continue

    return processed_orders

@app.route('/shopify/fetch_orders', methods=['POST'])
@login_required
@retry_on_db_lock()
def fetch_shopify_orders():
    credentials, error = require_integration(ShopifyCredentials, 'Shopify')
    if error:
        return error
    if not shopify_shop_domain(credentials):
        return jsonify({'error': 'Set the Shopify store domain (your-store.myshopify.com) '
                                 'on the Management page.'}), 400

    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    if not start_date or not end_date:
        return jsonify({'error': 'Start date and end date are required'}), 400
    try:
        datetime.strptime(start_date, '%Y-%m-%d')
        datetime.strptime(end_date, '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

    try:
        raw_orders = shopify_fetch_order_pages(credentials, start_date, end_date)
    except IntegrationError as e:
        return jsonify({'error': str(e)}), 502

    if not raw_orders:
        return jsonify({'message': 'No Shopify orders in that date range.', 'errors': []}), 200

    try:
        result = import_processed_orders(
            process_shopify_data(raw_orders), 'shopify')
    except IntegrationError as e:
        return jsonify({'error': str(e)}), 500

    return import_response('Shopify', result)

def verify_shopify_webhook(credentials, raw_body):
    """Constant-time check of the X-Shopify-Hmac-Sha256 header.

    Shopify signs the exact bytes of the request body with the app's API secret,
    so the raw body must be read before anything parses it.
    """
    provided = request.headers.get('X-Shopify-Hmac-Sha256', '')
    if not provided:
        return False
    secret = shopify_webhook_secret(credentials)
    if not secret:
        return False
    expected = base64.b64encode(
        hmac.new(secret.encode('utf-8'), raw_body, hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(expected, provided)

@app.route('/shopify/webhook', methods=['POST'])
def shopify_webhook():
    """Receive orders/create, orders/updated and orders/fulfilled from Shopify.

    Unauthenticated by design — Shopify cannot log in. The HMAC signature is the
    credential, so an unsigned or mis-signed request is rejected before the body
    is parsed. Returns 404 unless webhooks are explicitly switched on, so the
    endpoint does not exist for anyone scanning the host.

    Deliveries are at-least-once: repeats are safe because the importer matches
    on (source='shopify', external_order_id) and updates in place.
    """
    credentials = ShopifyCredentials.query.first()
    if not credentials or not credentials.enabled or not credentials.webhooks_enabled:
        abort(404)
    if not credentials.api_secret:
        app.logger.error('Shopify webhook arrived but no API secret is configured to verify it')
        abort(404)

    raw_body = request.get_data()
    if not verify_shopify_webhook(credentials, raw_body):
        app.logger.warning(f"Rejected Shopify webhook with an invalid HMAC from {request.remote_addr}")
        abort(401)

    shop = (request.headers.get('X-Shopify-Shop-Domain') or '').lower()
    configured = shopify_shop_domain(credentials).lower()
    if configured and shop != configured:
        app.logger.warning(f"Rejected Shopify webhook for unexpected shop {shop!r}")
        abort(401)

    topic = request.headers.get('X-Shopify-Topic', 'unknown')
    try:
        payload = json.loads(raw_body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        app.logger.error(f"Shopify webhook {topic} had an unparseable body")
        abort(400)

    processed = process_shopify_data([payload])
    if not processed:
        # Test or cancelled order — acknowledge so Shopify stops retrying
        app.logger.info(f"Shopify webhook {topic}: nothing to import")
        return jsonify({'status': 'ignored'}), 200

    try:
        result = import_processed_orders(processed, 'shopify')
    except IntegrationError as e:
        # 5xx so Shopify retries with backoff
        app.logger.error(f"Shopify webhook {topic} could not be saved: {e}")
        return jsonify({'status': 'error'}), 500

    if result.errors:
        app.logger.error(f"Shopify webhook {topic} import errors: {result.errors}")
        return jsonify({'status': 'error', 'errors': result.errors}), 500

    app.logger.info(f"Shopify webhook {topic}: created {result.created}, "
                    f"updated {result.updated}, adopted {result.adopted}, "
                    f"pending {result.pending}")
    return jsonify({'status': 'ok', 'created': result.created, 'updated': result.updated,
                    'adopted': result.adopted, 'pending': result.pending}), 200

# ---------------------------------------------------------------------------
# OAuth 2.0 marketplaces (Etsy, eBay)
#
# Unlike Shippo/ShipStation/WooCommerce (a key in a header) or Shopify on its own
# store (a key exchanged for a token with no human involved), Etsy and eBay
# require the *seller* to approve the app in a browser. That means a consent
# round trip, and the machinery below is shared by both:
#
#   1. "Connect" builds an authorize URL carrying a one-shot state nonce.
#   2. The seller approves and is redirected back with ?code=...
#   3. The code is exchanged for an access token + a long-lived refresh token.
#   4. Later fetches silently renew the access token from the refresh token.
#
# Step 2 needs the browser to reach this machine. On a LAN-only box that is not
# always true, so every connector also accepts the code pasted by hand — the
# redirect lands on a page showing the code, and Management takes it. Same
# exchange either way.
# ---------------------------------------------------------------------------

class OAuthSpec:
    """The per-platform parts of the flow above.

    authorize_url / token_url may be callables taking the credentials row, since
    eBay's hosts differ between sandbox and production.
    """

    def __init__(self, authorize_url, token_url, scopes, redirect_endpoint,
                 uses_pkce=False, redirect_value=None, auth_style='basic',
                 extra_authorize_params=None, docs_url=''):
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.scopes = scopes
        self.redirect_endpoint = redirect_endpoint
        self.uses_pkce = uses_pkce
        # eBay sends its RuName alias where Etsy sends the real redirect URI
        self.redirect_value = redirect_value
        self.auth_style = auth_style  # 'basic' (eBay) or 'body' (Etsy)
        self.extra_authorize_params = extra_authorize_params or {}
        self.docs_url = docs_url

    def resolve(self, attr, credentials):
        value = getattr(self, attr)
        return value(credentials) if callable(value) else value

# Renew a little early so a token cannot expire mid-import
OAUTH_TOKEN_SAFETY_MARGIN = timedelta(minutes=5)

def clear_oauth_tokens(credentials):
    """Forget every token. Used when the app credentials themselves change."""
    credentials.access_token = ''
    credentials.refresh_token = ''
    credentials.access_token_expires_at = None
    credentials.refresh_token_expires_at = None

def oauth_redirect_uri(spec):
    """The absolute callback URL, which must match what is registered upstream."""
    return url_for(spec.oauth.redirect_endpoint, _external=True)

def oauth_begin(spec, credentials):
    """Build the consent URL and stash the state/verifier for the callback."""
    oauth = spec.oauth
    client_id = spec.setting(credentials, 'client_id')
    if not client_id:
        raise IntegrationError(f'Enter the {spec.label} client ID and secret before connecting.')

    state = secrets.token_urlsafe(24)
    credentials.oauth_state = state
    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': oauth.redirect_value(credentials) if callable(oauth.redirect_value)
                        else (oauth.redirect_value or oauth_redirect_uri(spec)),
        'scope': ' '.join(oauth.scopes),
        'state': state,
        **oauth.extra_authorize_params,
    }

    if oauth.uses_pkce:
        # Etsy requires S256; the verifier never leaves this machine
        verifier = secrets.token_urlsafe(64)[:128]
        credentials.oauth_verifier = verifier
        digest = hashlib.sha256(verifier.encode('ascii')).digest()
        params['code_challenge'] = base64.urlsafe_b64encode(digest).decode().rstrip('=')
        params['code_challenge_method'] = 'S256'
    else:
        credentials.oauth_verifier = ''

    db.session.commit()
    return f"{oauth.resolve('authorize_url', credentials)}?{urlencode(params)}"

def oauth_token_request(spec, credentials, payload):
    """POST to the token endpoint and persist whatever came back."""
    oauth = spec.oauth
    client_id = spec.setting(credentials, 'client_id')
    client_secret = spec.setting(credentials, 'client_secret')
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    if oauth.auth_style == 'basic':
        pair = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
        headers['Authorization'] = f'Basic {pair}'
    else:
        payload = {**payload, 'client_id': client_id}
        if client_secret:
            payload['client_secret'] = client_secret

    response = integration_request(
        'POST', oauth.resolve('token_url', credentials), spec.label,
        data=payload, headers=headers)

    try:
        body = response.json()
    except ValueError:
        raise IntegrationError(f'{spec.label} returned an unreadable token response.')

    token = body.get('access_token')
    if not token:
        raise IntegrationError(
            f"{spec.label} did not return an access token: {body.get('error_description') or body}")

    credentials.access_token = token
    credentials.access_token_expires_at = (
        datetime.now() + timedelta(seconds=int(body.get('expires_in') or 3600)))
    if body.get('refresh_token'):
        credentials.refresh_token = body['refresh_token']
        # eBay reports the refresh token's own lifetime; Etsy's does not expire
        if body.get('refresh_token_expires_in'):
            credentials.refresh_token_expires_at = (
                datetime.now() + timedelta(seconds=int(body['refresh_token_expires_in'])))

    db.session.commit()
    app.logger.info(f"{spec.label}: stored an access token valid for "
                    f"{body.get('expires_in')}s")
    return token

def oauth_complete(spec, credentials, code, state=None):
    """Exchange an authorization code. `state` is checked when the callback supplies it."""
    if state is not None:
        expected = (credentials.oauth_state or '').strip()
        if not expected or not hmac.compare_digest(expected, state):
            raise IntegrationError(
                f'{spec.label} sent back an unexpected state value. Start the '
                f'connection again from Management.')

    oauth = spec.oauth
    payload = {
        'grant_type': 'authorization_code',
        'code': code.strip(),
        'redirect_uri': oauth.redirect_value(credentials) if callable(oauth.redirect_value)
                        else (oauth.redirect_value or oauth_redirect_uri(spec)),
    }
    if oauth.uses_pkce:
        payload['code_verifier'] = credentials.oauth_verifier or ''

    token = oauth_token_request(spec, credentials, payload)
    # The nonce and verifier are single-use
    credentials.oauth_state = ''
    credentials.oauth_verifier = ''
    db.session.commit()
    return token

def oauth_access_token(spec, credentials):
    """A usable access token, renewed from the refresh token when it is stale."""
    cached = (credentials.access_token or '').strip()
    expires_at = credentials.access_token_expires_at
    if cached and expires_at and datetime.now() + OAUTH_TOKEN_SAFETY_MARGIN < expires_at:
        return cached

    refresh = (credentials.refresh_token or '').strip()
    if not refresh:
        raise IntegrationError(
            f'{spec.label} is not connected yet. Open Management and click '
            f'Connect {spec.label}.')

    if (credentials.refresh_token_expires_at
            and datetime.now() >= credentials.refresh_token_expires_at):
        raise IntegrationError(
            f'The {spec.label} connection has expired. Open Management and '
            f'reconnect.')

    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh}
    if spec.oauth.auth_style == 'basic':
        # eBay requires the scopes to be restated when refreshing
        payload['scope'] = ' '.join(spec.oauth.scopes)
    return oauth_token_request(spec, credentials, payload)

def oauth_status(spec):
    """What Management shows about the connection, without exposing any token."""
    credentials = spec.credentials()
    if credentials is None:
        return {'connected': False, 'expires_at': None, 'redirect_uri': ''}
    return {
        'connected': bool((credentials.refresh_token or '').strip()),
        'expires_at': credentials.access_token_expires_at,
        'redirect_uri': oauth_redirect_uri(spec),
    }

@app.route('/integrations/<key>/connect', methods=['POST'])
@login_required
def integration_connect(key):
    """Start the consent round trip for an OAuth marketplace."""
    spec = INTEGRATIONS.get(key)
    if spec is None or spec.oauth is None:
        abort(404)

    # The button lives inside the Management form, so save what was typed before
    # sending the operator off to the marketplace — otherwise a client ID pasted
    # a moment ago would not be there when they came back.
    if request.form:
        try:
            _save_integration_credentials(request.form)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Could not save credentials before connecting {key}: {e}")
            flash('Could not save those credentials.', 'error')
            return redirect(url_for('management'))

    credentials = spec.credentials()
    if credentials is None:
        credentials = spec.model()
        db.session.add(credentials)
        db.session.commit()
    try:
        return redirect(oauth_begin(spec, credentials))
    except IntegrationError as e:
        db.session.rollback()
        flash(str(e), 'error')
        return redirect(url_for('management'))

@app.route('/integrations/<key>/callback')
@login_required
def integration_callback(key):
    """Where the marketplace sends the seller back with ?code=…

    Login is required, so a stray hit from anyone who is not already signed in
    goes to the login page rather than into the token exchange.
    """
    spec = INTEGRATIONS.get(key)
    if spec is None or spec.oauth is None:
        abort(404)

    error = request.args.get('error_description') or request.args.get('error')
    if error:
        flash(f'{spec.label} declined the connection: {error}', 'error')
        return redirect(url_for('management'))

    code = request.args.get('code')
    if not code:
        flash(f'{spec.label} sent no authorization code.', 'error')
        return redirect(url_for('management'))

    credentials = spec.credentials()
    if credentials is None:
        flash(f'Save the {spec.label} credentials first.', 'error')
        return redirect(url_for('management'))

    try:
        oauth_complete(spec, credentials, code, state=request.args.get('state'))
    except IntegrationError as e:
        db.session.rollback()
        flash(str(e), 'error')
        return redirect(url_for('management'))

    flash(f'{spec.label} connected.', 'success')
    return redirect(url_for('management'))

@app.route('/integrations/<key>/paste_code', methods=['POST'])
@login_required
def integration_paste_code(key):
    """Fallback for when the redirect cannot reach this machine.

    The seller approves in any browser, copies the `code` out of the address bar
    and pastes it here. The state check is skipped — there is no round trip to
    tie it to — so the code itself is the only credential, exactly as in the
    redirect case.
    """
    spec = INTEGRATIONS.get(key)
    if spec is None or spec.oauth is None:
        abort(404)
    credentials = spec.credentials()
    if credentials is None:
        flash(f'Save the {spec.label} credentials first.', 'error')
        return redirect(url_for('management'))

    code = (request.form.get('code') or '').strip()
    if not code:
        flash('Paste the authorization code first.', 'error')
        return redirect(url_for('management'))
    # Tolerate a whole pasted URL
    if 'code=' in code:
        code = parse_qs(urlparse(code).query).get('code', [code])[0]

    try:
        oauth_complete(spec, credentials, code)
    except IntegrationError as e:
        db.session.rollback()
        flash(str(e), 'error')
        return redirect(url_for('management'))

    flash(f'{spec.label} connected.', 'success')
    return redirect(url_for('management'))

@app.route('/integrations/<key>/disconnect', methods=['POST'])
@login_required
def integration_disconnect(key):
    spec = INTEGRATIONS.get(key)
    if spec is None or spec.oauth is None:
        abort(404)
    credentials = spec.credentials()
    if credentials is not None:
        clear_oauth_tokens(credentials)
        db.session.commit()
    flash(f'{spec.label} disconnected.', 'info')
    return redirect(url_for('management'))

# ---------------------------------------------------------------------------
# Etsy — Open API v3
#
# Receipts, not "orders": one receipt is one buyer checkout and carries the
# transactions (line items) plus the shipping address. Money arrives as
# {amount, divisor} integers, never floats.
# ---------------------------------------------------------------------------

ETSY_SCOPES = ('transactions_r', 'listings_r', 'shops_r')

def etsy_money(value):
    """Etsy sends {'amount': 1250, 'divisor': 100} rather than 12.50."""
    if not isinstance(value, dict):
        return Decimal('0')
    divisor = Decimal(str(value.get('divisor') or 100))
    if divisor == 0:
        return Decimal('0')
    return (Decimal(str(value.get('amount') or 0)) / divisor).quantize(Decimal('0.01'))

def etsy_api_key(spec, credentials):
    """Etsy's x-api-key is *both* credentials joined: 'keystring:shared_secret'.

    Not the keystring alone, which is what the OAuth client_id is. Sending only
    the keystring is refused with "Shared secret is required in x-api-key
    header"; sending an empty header makes Etsy spell the format out.
    """
    keystring = spec.setting(credentials, 'client_id')
    shared_secret = spec.setting(credentials, 'client_secret')
    if not keystring or not shared_secret:
        raise IntegrationError(
            'Etsy needs both the keystring and the shared secret — it sends them '
            'together in one header. Add the missing one on the Management page.')
    return f'{keystring}:{shared_secret}'

def etsy_headers(spec, credentials):
    return {
        'x-api-key': etsy_api_key(spec, credentials),
        'Authorization': f'Bearer {oauth_access_token(spec, credentials)}',
    }

def etsy_shop_id(spec, credentials):
    """The numeric shop id, discovered from the token's own user if not stored."""
    stored = spec.setting(credentials, 'shop_id')
    if stored:
        return stored

    response = integration_request(
        'GET', 'https://openapi.etsy.com/v3/application/users/me', spec.label,
        headers=etsy_headers(spec, credentials))
    shop_id = str((response.json() or {}).get('shop_id') or '')
    if not shop_id:
        raise IntegrationError(
            'Could not determine the Etsy shop id for this account. Enter it on '
            'the Management page.')

    credentials.shop_id = shop_id
    db.session.commit()
    app.logger.info(f'Etsy shop id discovered: {shop_id}')
    return shop_id

def etsy_fetch_receipts(credentials, start_date, end_date, max_pages=100):
    """Page the receipts endpoint over a date range. Etsy filters on epoch seconds."""
    spec = INTEGRATIONS['etsy']
    shop_id = etsy_shop_id(spec, credentials)
    min_created = int(datetime.combine(start_date, dt_time.min).timestamp())
    max_created = int(datetime.combine(end_date, dt_time.max).timestamp())

    receipts = []
    limit, offset = 100, 0
    for page in range(max_pages):
        response = integration_request(
            'GET', f'https://openapi.etsy.com/v3/application/shops/{shop_id}/receipts',
            spec.label,
            params={'min_created': min_created, 'max_created': max_created,
                    'limit': limit, 'offset': offset},
            headers=etsy_headers(spec, credentials))
        body = response.json() or {}
        batch = body.get('results') or []
        receipts.extend(batch)
        app.logger.info(f'Etsy page {page + 1}: {len(batch)} receipt(s)')
        if len(batch) < limit:
            break
        offset += limit
    else:
        app.logger.warning(f'Stopped paging Etsy receipts at {max_pages} pages')

    return receipts

def process_etsy_data(receipts):
    """Translate Etsy receipts into the shape import_processed_orders wants."""
    processed = []
    for receipt in receipts:
        try:
            if receipt.get('status') == 'Canceled':
                app.logger.info(f"Skipping cancelled Etsy receipt {receipt.get('receipt_id')}")
                continue

            name = (receipt.get('name') or '').strip()
            customer_data = {
                'name': name or 'Unknown',
                'email': receipt.get('buyer_email') or '',
                'company': '',
                'street1': receipt.get('first_line') or '',
                'street2': receipt.get('second_line') or '',
                'street3': '',
                'city': receipt.get('city') or '',
                # Etsy sends the full state name for US addresses; get_state_info
                # wants the USPS abbreviation, so normalise here
                'state': us_state_code(receipt.get('state')),
                'postal_code': receipt.get('zip') or '',
                'country': receipt.get('country_iso') or '',
                'phone': '',
            }
            customer_data_unavailable = not any([
                customer_data['email'], name,
                customer_data['street1'], customer_data['postal_code'],
            ])

            created = receipt.get('created_timestamp') or receipt.get('create_timestamp')
            order_date = (datetime.fromtimestamp(int(created)) if created else datetime.now())

            shipservice = tracking = shipdate = None
            for shipment in receipt.get('shipments') or []:
                tracking = shipment.get('tracking_code') or tracking
                carrier = (shipment.get('carrier_name') or '').strip()
                if carrier:
                    shipservice = carrier.split()[0].upper()
                shipped = shipment.get('shipment_notification_timestamp')
                if shipped:
                    shipdate = datetime.fromtimestamp(int(shipped)).date()

            items = []
            for line in receipt.get('transactions') or []:
                quantity = int(line.get('quantity') or 0)
                if quantity < 1:
                    continue
                items.append({
                    'sku': line.get('sku') or line.get('title') or 'Unknown SKU',
                    'name': line.get('title') or 'Unknown Item',
                    'quantity': quantity,
                    'unit_price': etsy_money(line.get('price')),
                })

            internal_notes = 'Imported from Etsy'
            if customer_data_unavailable:
                internal_notes += ' — Etsy withheld the buyer details for this receipt.'

            processed.append({
                'external_order_id': str(receipt['receipt_id']),
                'external_order_number': str(receipt.get('receipt_id')),
                'order_date': order_date,
                'shipservice': shipservice,
                'tracking': tracking,
                'shipdate': shipdate,
                'customer': customer_data,
                'customer_data_unavailable': customer_data_unavailable,
                'items': items,
                'order_total': etsy_money(receipt.get('grandtotal')),
                'tax_amount': etsy_money(receipt.get('total_tax_cost')),
                'shipping_amount': etsy_money(receipt.get('total_shipping_cost')),
                'customer_notes': receipt.get('message_from_buyer') or '',
                'internal_notes': internal_notes,
            })
        except Exception as e:
            app.logger.error(
                f"Skipping malformed Etsy receipt {receipt.get('receipt_id', 'Unknown')}: {e}")
            continue

    return processed

# ---------------------------------------------------------------------------
# eBay — Sell Fulfillment API
#
# Reading orders needs a *user* token, not the application token that client
# credentials would give you, which is why eBay goes through the same consent
# flow as Etsy. eBay also anonymises buyer contact details on most orders, so
# expect these to land in the pending queue rather than becoming sales outright.
# ---------------------------------------------------------------------------

EBAY_SCOPES = ('https://api.ebay.com/oauth/api_scope/sell.fulfillment.readonly',)

def ebay_host(credentials, subdomain):
    suffix = 'sandbox.ebay.com' if getattr(credentials, 'sandbox', False) else 'ebay.com'
    return f'https://{subdomain}.{suffix}'

def ebay_money(value):
    """eBay amounts arrive as {'value': '12.50', 'currency': 'USD'}."""
    if not isinstance(value, dict):
        return Decimal('0')
    try:
        return Decimal(str(value.get('value') or '0'))
    except InvalidOperation:
        return Decimal('0')

def ebay_fetch_orders(credentials, start_date, end_date, max_pages=100):
    spec = INTEGRATIONS['ebay']
    token = oauth_access_token(spec, credentials)
    # eBay's creationdate filter wants UTC instants in this exact bracket form
    start = datetime.combine(start_date, dt_time.min).astimezone().astimezone(
        timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    end = datetime.combine(end_date, dt_time.max).astimezone().astimezone(
        timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')

    url = f"{ebay_host(credentials, 'api')}/sell/fulfillment/v1/order"
    params = {'filter': f'creationdate:[{start}..{end}]', 'limit': 200, 'offset': 0}
    orders = []
    for page in range(max_pages):
        response = integration_request(
            'GET', url, spec.label, params=params,
            headers={'Authorization': f'Bearer {token}',
                     'Accept': 'application/json'})
        body = response.json() or {}
        batch = body.get('orders') or []
        orders.extend(batch)
        app.logger.info(f'eBay page {page + 1}: {len(batch)} order(s)')
        if len(batch) < params['limit']:
            break
        params = {**params, 'offset': params['offset'] + params['limit']}
    else:
        app.logger.warning(f'Stopped paging eBay orders at {max_pages} pages')

    return orders

def parse_ebay_datetime(value):
    """eBay timestamps are UTC ISO 8601 with a Z; store naive local like everything else."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        app.logger.warning(f'Unparseable eBay timestamp: {value!r}')
        return None
    return parsed.astimezone().replace(tzinfo=None) if parsed.tzinfo else parsed

def process_ebay_data(ebay_orders):
    """Translate eBay orders into the shape import_processed_orders wants."""
    processed = []
    for order in ebay_orders:
        try:
            if (order.get('orderPaymentStatus') or '') == 'FAILED':
                app.logger.info(f"Skipping unpaid eBay order {order.get('orderId')}")
                continue

            ship_to = {}
            for instruction in order.get('fulfillmentStartInstructions') or []:
                ship_to = ((instruction.get('shippingStep') or {}).get('shipTo')) or {}
                if ship_to:
                    break
            address = ship_to.get('contactAddress') or {}
            name = (ship_to.get('fullName') or '').strip()

            customer_data = {
                'name': name or 'Unknown',
                'email': ship_to.get('email') or '',
                'company': '',
                'street1': address.get('addressLine1') or '',
                'street2': address.get('addressLine2') or '',
                'street3': '',
                'city': address.get('city') or '',
                'state': us_state_code(address.get('stateOrProvince')),
                'postal_code': address.get('postalCode') or '',
                'country': address.get('countryCode') or '',
                'phone': (ship_to.get('primaryPhone') or {}).get('phoneNumber') or '',
            }
            # eBay anonymises buyer contact details on most orders
            customer_data_unavailable = not any([
                customer_data['email'], name,
                customer_data['street1'], customer_data['postal_code'],
            ])

            pricing = order.get('pricingSummary') or {}
            order_date = parse_ebay_datetime(order.get('creationDate')) or datetime.now()

            # Tracking is only present when the order payload embeds
            # shippingFulfillments; eBay otherwise exposes it behind a per-order
            # call, which a later pass can add if it turns out to matter.
            shipservice = tracking = shipdate = None
            for fulfillment in order.get('shippingFulfillments') or []:
                tracking = fulfillment.get('shipmentTrackingNumber') or tracking
                carrier = (fulfillment.get('shippingCarrierCode') or '').strip()
                if carrier:
                    shipservice = carrier.split()[0].upper()
                shipped = parse_ebay_datetime(fulfillment.get('shippedDate'))
                if shipped:
                    shipdate = shipped.date()

            items = []
            for line in order.get('lineItems') or []:
                quantity = int(line.get('quantity') or 0)
                if quantity < 1:
                    continue
                unit = ebay_money(line.get('lineItemCost'))
                items.append({
                    'sku': line.get('sku') or line.get('legacyItemId') or line.get('title') or 'Unknown SKU',
                    'name': line.get('title') or 'Unknown Item',
                    'quantity': quantity,
                    'unit_price': unit,
                })

            internal_notes = 'Imported from eBay'
            if customer_data_unavailable:
                internal_notes += (' — eBay withheld the buyer details for this order. '
                                   'Enter the customer by hand.')

            processed.append({
                'external_order_id': str(order['orderId']),
                'external_order_number': str(order.get('legacyOrderId') or order['orderId']),
                'order_date': order_date,
                'shipservice': shipservice,
                'tracking': tracking,
                'shipdate': shipdate,
                'customer': customer_data,
                'customer_data_unavailable': customer_data_unavailable,
                'items': items,
                'order_total': ebay_money(pricing.get('total')),
                'tax_amount': ebay_money(pricing.get('tax')),
                'shipping_amount': ebay_money(pricing.get('deliveryCost')),
                'customer_notes': order.get('buyerCheckoutNotes') or '',
                'internal_notes': internal_notes,
            })
        except Exception as e:
            app.logger.error(
                f"Skipping malformed eBay order {order.get('orderId', 'Unknown')}: {e}")
            continue

    return processed

# ---------------------------------------------------------------------------
# The registry
#
# Everything above is platform-specific; everything below is generic. Adding a
# marketplace means adding one entry here plus its fetch/process pair — the
# Management form, the environment overrides, the dashboard card, the fetch
# route and (if it needs one) the OAuth round trip all follow from this.
# ---------------------------------------------------------------------------

def _register(spec):
    INTEGRATIONS[spec.key] = spec
    return spec

def build_integration_registry():
    """Populate INTEGRATIONS.

    Deferred to a function and called at the bottom of this module because the
    entries below name each platform's fetch/process pair, and some of those are
    defined further down the file.
    """
    _register(IntegrationSpec(
        key='shopify', label='Shopify', model=ShopifyCredentials,
        secret_fields=('api_key', 'api_secret', 'client_id', 'client_secret'),
        plain_fields=('shop_domain',),
        bool_fields=('webhooks_enabled',),
        env_fields=SHOPIFY_ENV_FIELDS,
        fetch=lambda credentials, start, end: shopify_fetch_order_pages(
            credentials, start.isoformat(), end.isoformat()),
        process=process_shopify_data,
        blurb='Orders from a Shopify store.'))

    _register(IntegrationSpec(
        key='shipstation', label='ShipStation', model=ShipStationCredentials,
        form_prefix='ss', secret_fields=('api_key', 'api_secret'),
        fetch=shipstation_fetch_orders, process=process_shipstation_data,
        enrich=shipstation_enrich,
        blurb='Orders and shipments from ShipStation.'))

    _register(IntegrationSpec(
        key='shippo', label='Shippo', model=ShippoCredentials,
        secret_fields=('api_key',),
        fetch=shippo_fetch_orders, process=process_shippo_data,
        empty_message='No shipped Shippo orders in that date range. Shippo creates '
                      'orders when you buy a label or connect a storefront.',
        blurb='Shipped orders from Shippo.'))

    _register(IntegrationSpec(
        key='woocommerce', label='WooCommerce', model=WooCommerceCredentials,
        form_prefix='wc', secret_fields=('api_key', 'api_secret'),
        blurb='Orders from a WooCommerce store. Not implemented yet.'))

    _register(IntegrationSpec(
        key='etsy', label='Etsy', model=EtsyCredentials,
        secret_fields=('client_id', 'client_secret'), plain_fields=('shop_id',),
        # Etsy's own words. client_id/client_secret are only how they are stored.
        field_labels={'client_id': 'Keystring', 'client_secret': 'Shared Secret',
                      'shop_id': 'Shop ID'},
        field_hints={
            'client_id': 'Your app\'s keystring, from the Etsy developer console. '
                         'Also sent as the OAuth client ID.',
            'client_secret': 'Your app\'s shared secret. Etsy needs it for every '
                             'API call, not just for sign-in — the two are sent '
                             'together as "keystring:shared_secret".',
        },
        env_fields={
            'client_id': ('ETSY_KEYSTRING', 'ETSY_CLIENT_ID'),
            'client_secret': ('ETSY_SHAREDSECRET', 'ETSY_CLIENT_SECRET'),
            'shop_id': ('ETSY_SHOP_ID',),
        },
        fetch=etsy_fetch_receipts, process=process_etsy_data,
        oauth=OAuthSpec(
            authorize_url='https://www.etsy.com/oauth/connect',
            token_url='https://api.etsy.com/v3/public/oauth/token',
            scopes=ETSY_SCOPES,
            redirect_endpoint='integration_callback_etsy',
            uses_pkce=True, auth_style='body',
            docs_url='https://developers.etsy.com/documentation/essentials/authentication'),
        blurb='Receipts from an Etsy shop.'))

    _register(IntegrationSpec(
        key='ebay', label='eBay', model=EbayCredentials,
        secret_fields=('client_id', 'client_secret'), plain_fields=('ru_name',),
        bool_fields=('sandbox',),
        # eBay's developer console calls these the App ID and Cert ID
        field_labels={'client_id': 'App ID (Client ID)',
                      'client_secret': 'Cert ID (Client Secret)',
                      'ru_name': 'RuName (redirect alias)',
                      'sandbox': 'Use the eBay sandbox'},
        env_fields={
            'client_id': ('EBAY_APP_ID', 'EBAY_CLIENT_ID'),
            'client_secret': ('EBAY_CERT_ID', 'EBAY_CLIENT_SECRET'),
            'ru_name': ('EBAY_RU_NAME',),
        },
        fetch=ebay_fetch_orders, process=process_ebay_data,
        oauth=OAuthSpec(
            authorize_url=lambda c: f"{ebay_host(c, 'auth')}/oauth2/authorize",
            token_url=lambda c: f"{ebay_host(c, 'api')}/identity/v1/oauth2/token",
            scopes=EBAY_SCOPES,
            redirect_endpoint='integration_callback_ebay',
            # eBay sends the RuName alias, not the URL, in both calls
            redirect_value=lambda c: (c.ru_name or '').strip(),
            auth_style='basic',
            docs_url='https://developer.ebay.com/api-docs/static/oauth-authorization-code-grant.html'),
        blurb='Orders from an eBay seller account.'))

# Named callback endpoints, so each platform can be given a stable redirect URI
# to register upstream rather than one with a path parameter in it.
@app.route('/etsy/callback')
@login_required
def integration_callback_etsy():
    return integration_callback('etsy')

@app.route('/ebay/callback')
@login_required
def integration_callback_ebay():
    return integration_callback('ebay')

def requested_date_range():
    """Pull and validate start_date/end_date off an import form."""
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    if not start_date or not end_date:
        return None, None, (jsonify({'error': 'Start date and end date are required'}), 400)
    try:
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
    except ValueError:
        return None, None, (jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400)
    if end < start:
        return None, None, (jsonify({'error': 'The end date is before the start date.'}), 400)
    return start, end, None

def run_integration_import(key):
    """Fetch a date range from one platform and import it. Shared by every route."""
    spec = INTEGRATIONS.get(key)
    if spec is None or spec.fetch is None:
        return jsonify({'error': f'No importer is implemented for {key}.'}), 501

    credentials, error = require_integration(spec.model, spec.label)
    if error:
        return error

    start, end, error = requested_date_range()
    if error:
        return error

    try:
        raw_orders = spec.fetch(credentials, start, end)
    except IntegrationError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 502

    if not raw_orders:
        return jsonify({'message': spec.empty_message
                                   or f'No {spec.label} orders in that date range.',
                        'errors': []}), 200

    try:
        result = import_processed_orders(
            spec.process(raw_orders), spec.key,
            enrich=spec.enrich(credentials) if spec.enrich else None)
    except IntegrationError as e:
        return jsonify({'error': str(e)}), 500

    return import_response(spec.label, result)

@app.route('/integrations/<key>/fetch_orders', methods=['POST'])
@login_required
@retry_on_db_lock()
def fetch_integration_orders(key):
    if key not in INTEGRATIONS:
        abort(404)
    return run_integration_import(key)

@app.route('/etsy/fetch_orders', methods=['POST'])
@login_required
@retry_on_db_lock()
def fetch_etsy_orders():
    return run_integration_import('etsy')

@app.route('/ebay/fetch_orders', methods=['POST'])
@login_required
@retry_on_db_lock()
def fetch_ebay_orders():
    return run_integration_import('ebay')

@app.route('/finance')
@login_required
def finance():
    company_info = CompanyInfo.get_info()
    return render_template('finance.html', company_info=company_info)

@app.route('/finance/banking')
@login_required
def banking():
    company_info = CompanyInfo.get_info()
    return render_template('banking.html', company_info=company_info)

@app.route('/finance/upload_transactions', methods=['POST'])
@login_required
def upload_transactions():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'File must be CSV format'}), 400

    try:
        file_content = file.stream.read().decode("utf-8-sig")
        stream = io.StringIO(file_content)
        csv_data = csv.DictReader(stream)
        
        transactions = []
        duplicates = 0
        row_count = 0
        
        for row in csv_data:
            row_count += 1
            try:
                date_str = row['Booking Date']
                if not date_str:
                    continue
                    
                try:
                    date = datetime.strptime(date_str.strip(), '%m/%d/%Y').date()
                except ValueError:
                    continue
                
                amount_str = row['Amount']
                if not amount_str:
                    continue
                    
                try:
                    amount = float(amount_str.strip().replace('$', '').replace(',', ''))
                except ValueError:
                    continue

                transaction = BankTransaction(
                    date=date,
                    description=row['Description'].strip(),
                    amount=amount,
                    credit_debit=row['Credit Debit Indicator'].strip(),
                    transaction_type=row['type'].strip(),
                    category=row['Category'].strip(),
                    check_number=row['Check Serial Number'].strip() if row['Check Serial Number'] else '',
                    notes=''
                )
                
                # Check for duplicates before adding
                if not is_duplicate_transaction(transaction):
                    db.session.add(transaction)
                    transactions.append(transaction)
                else:
                    duplicates += 1
                
            except Exception as e:
                app.logger.error(f"Row {row_count}: Error processing row: {str(e)}")
                continue

        if not transactions and duplicates == 0:
            return jsonify({'error': 'No valid transactions could be processed from the file'}), 400
            
        db.session.commit()
        return jsonify({
            'success': True, 
            'message': f'Successfully imported {len(transactions)} transactions. Skipped {duplicates} duplicate entries.'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error processing file: {str(e)}'}), 400

@app.route('/api/link_receipt/<int:transaction_id>/<int:receipt_id>', methods=['POST'])
@login_required
def link_receipt(transaction_id, receipt_id):
    try:
        transaction = BankTransaction.query.get_or_404(transaction_id)
        # 404 early rather than storing a receipt_id that does not exist
        SalesReceipt.query.get_or_404(receipt_id)


        transaction.receipt_id = receipt_id
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/transactions')
@login_required
def get_transactions():
    try:
        # Get all transactions ordered by date descending
        transactions = BankTransaction.query.order_by(BankTransaction.date.desc()).all()
        
        # Convert to list of dictionaries
        transactions_list = [transaction.to_dict() for transaction in transactions]
        
        return jsonify(transactions_list)
    except Exception as e:
        app.logger.error(f"Error fetching transactions: {str(e)}")
        return jsonify({'error': f'Error fetching transactions: {str(e)}'}), 500

@app.route('/api/transaction/update/<int:id>', methods=['POST'])
@login_required
def update_transaction(id):
    transaction = BankTransaction.query.get_or_404(id)
    data = request.json
    
    if 'category' in data:
        transaction.category = data['category']
    if 'notes' in data:
        transaction.notes = data['notes']
        
    try:
        db.session.commit()
        return jsonify({'success': True})
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/transactions/delete/<int:id>', methods=['DELETE'])
@login_required
def delete_transaction(id):
    try:
        transaction = BankTransaction.query.get_or_404(id)
        db.session.delete(transaction)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/transactions/delete-multiple', methods=['POST'])
@login_required
def delete_multiple_transactions():
    try:
        transaction_ids = request.json.get('ids', [])
        if not transaction_ids:
            return jsonify({'error': 'No transaction IDs provided'}), 400
            
        BankTransaction.query.filter(BankTransaction.id.in_(transaction_ids)).delete(synchronize_session=False)
        db.session.commit()
        return jsonify({'success': True, 'count': len(transaction_ids)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


# Functions
def format_name(name):
    if not name:
        return 'Unknown'
    
    # Split the name into parts
    parts = re.findall(r"[\w'-]+", name)
    
    # Capitalize each part properly
    formatted_parts = []
    for part in parts:
        # Check if the part is an initial (single character)
        if len(part) == 1:
            formatted_parts.append(part.upper())
        else:
            # Capitalize the first letter, lowercase the rest
            formatted_parts.append(part.capitalize())
    
    # Join the parts back together
    return ' '.join(formatted_parts)

def get_or_create_customer(customer_data):
    """Match an imported order's customer by email on db.session, creating if new.

    Existing customers are never overwritten — addresses and names are routinely
    corrected by hand here, and the marketplace copy is not authoritative.
    """
    with db.session.no_autoflush:
        email = (customer_data.get('email') or '').strip()
        if not email:
            email = _placeholder_email()

        customer = Customer.query.filter_by(email=email).first()
        if customer:
            return customer

        address = format_address(customer_data)
        customer = Customer(
            name=format_name(customer_data.get('name', 'Unknown')),
            company=customer_data.get('company') or '',
            email=email,
            phone=customer_data.get('phone') or '',
            billing_address=address,
            shipping_address=address
        )
        db.session.add(customer)
        db.session.flush()
        return customer

def format_address(address_dict):
    country_code = address_dict.get('country', '')
    state_code = address_dict.get('state', '')
    country_full = get_country_name(country_code)

    if country_code == 'US':
        # Keep the state as abbreviation for US
        state_full = state_code
        country_full = ''  # Drop the country name for US addresses
    else:
        state_full = get_state_name(state_code, country_code)

    # "City, ST 98501" — but assembled from whatever is actually present. When a
    # platform withholds the street/city/ZIP (Shopify's protected customer data
    # rules) this must not degrade to ", CA", which get_state_info cannot read.
    city = title_capitalize(address_dict.get('city', '') or '')
    region_zip = ' '.join(part for part in [state_full, address_dict.get('postal_code', '')] if part).strip()
    locality = ', '.join(part for part in [city, region_zip] if part)

    address_parts = [
        title_capitalize(address_dict.get('street1', '')),
        title_capitalize(address_dict.get('street2', '')),
        title_capitalize(address_dict.get('street3', '')),
        locality,
        country_full
    ]

    # Filter out empty parts and join with newlines
    formatted_address = '\n'.join(part for part in address_parts if part).strip()

    return formatted_address

def title_capitalize(part):
    if part:
        return part.title()
    return part

def get_country_name(country_code):
    country = pycountry.countries.get(alpha_2=country_code)
    return country.name if country else country_code

def get_state_name(state_code, country_code):
    try:
        subdivisions = pycountry.subdivisions.get(country_code=country_code) or []
    except LookupError:
        return state_code
    for subdivision in subdivisions:
        if subdivision.code.split('-')[-1] == state_code:
            return subdivision.name
    return state_code

def _build_us_state_maps():
    abbr_to_name = {
        subdivision.code.split('-')[-1]: subdivision.name
        for subdivision in pycountry.subdivisions.get(country_code='US')
    }
    # USPS military "states" are not ISO 3166-2 subdivisions
    abbr_to_name.update({
        'AA': 'Armed Forces Americas',
        'AE': 'Armed Forces Europe',
        'AP': 'Armed Forces Pacific',
    })
    name_to_abbr = {name.replace('.', '').upper(): abbr for abbr, name in abbr_to_name.items()}
    return abbr_to_name, name_to_abbr

# All 50 states plus DC, territories (PR, GU, VI, AS, MP, UM), and military mail codes
US_STATE_ABBR_TO_NAME, US_STATE_NAME_TO_ABBR = _build_us_state_maps()

def us_state_code(value):
    """Normalise a US state to its USPS abbreviation, or pass the value through.

    Etsy sends full state names ("Washington") and eBay sends either, but
    get_state_info() — and so the WA B&O report — only recognises the
    abbreviation. An unrecognised value is returned unchanged rather than
    blanked, so a non-US province still reaches the address line intact.
    """
    text = str(value or '').strip()
    if not text:
        return ''
    if len(text) == 2 and text.upper() in US_STATE_ABBR_TO_NAME:
        return text.upper()
    return US_STATE_NAME_TO_ABBR.get(text.replace('.', '').upper(), text)

# Common spellings that pycountry.countries.lookup() cannot resolve, mapped to alpha-2 codes
COUNTRY_ALIASES = {
    'UK': 'GB',
    'GREAT BRITAIN': 'GB',
    'ENGLAND': 'GB',
    'SCOTLAND': 'GB',
    'WALES': 'GB',
    'NORTHERN IRELAND': 'GB',
    'SOUTH KOREA': 'KR',
    'KOREA': 'KR',
    'NORTH KOREA': 'KP',
    'RUSSIA': 'RU',
    'VIETNAM': 'VN',
    'LAOS': 'LA',
    'SYRIA': 'SY',
    'IVORY COAST': 'CI',
    'CAPE VERDE': 'CV',
    'BURMA': 'MM',
    'MACEDONIA': 'MK',
    'SWAZILAND': 'SZ',
    'ST LUCIA': 'LC',
    'ST KITTS AND NEVIS': 'KN',
    'ST VINCENT AND THE GRENADINES': 'VC',
    'THE NETHERLANDS': 'NL',
    'HOLLAND': 'NL',
    'UAE': 'AE',
    'DRC': 'CD',
}

# Keep report labels the app has historically used where pycountry's primary name differs
COUNTRY_DISPLAY_OVERRIDES = {
    'CZ': 'Czech Republic',
}

def find_country(text):
    """Resolve a country name or ISO code (any casing, with or without periods,
    e.g. 'USA', 'U.S.A.', 'united kingdom', 'South Korea') to a pycountry country, or None."""
    if not text:
        return None
    cleaned = text.replace('.', '').strip().strip(',').strip()
    if not cleaned:
        return None
    upper = cleaned.upper()
    # Bare two-letter US state abbreviations (CA, DE, IN, GA, ...) collide with
    # ISO country codes; in this app they always mean the state
    if upper in US_STATE_ABBR_TO_NAME:
        return None
    cleaned = COUNTRY_ALIASES.get(upper, cleaned)
    try:
        # Case-insensitive match on name, official name, common name, alpha-2/alpha-3
        return pycountry.countries.lookup(cleaned)
    except LookupError:
        return None

def country_display_name(country):
    override = COUNTRY_DISPLAY_OVERRIDES.get(country.alpha_2)
    if override:
        return override
    return getattr(country, 'common_name', country.name)

def normalize_us_state(region):
    """Return the USPS abbreviation for a US state/territory given either an
    abbreviation ('wa', 'D.C.') or a full name ('Washington'), else None."""
    if not region:
        return None
    cleaned = region.replace('.', '').strip().upper()
    if cleaned in US_STATE_ABBR_TO_NAME:
        return cleaned
    return US_STATE_NAME_TO_ABBR.get(cleaned)

def get_state_info(address):
    """Extract the state/country used for tax reporting from a shipping address:
    'City, WA ZIP' for Washington, the USPS abbreviation for other US states,
    or the country name for non-US addresses."""
    if not address:
        return 'Unknown'

    lines = [line.strip() for line in address.split('\n') if line.strip()]
    if not lines:
        return 'Unknown'

    # Matches "City, Region" or "City, Region ZIP" where Region may be an
    # abbreviation or a spelled-out state name
    city_region_pattern = re.compile(
        r'^(?P<city>.+),\s*(?P<region>[A-Za-z][A-Za-z. ]*?)[,\s]*(?P<zip>\d{5}(?:-\d{4})?)?$'
    )
    # Matches "City ST ZIP" with no comma ("Lebanon TN 37087"); the ZIP is
    # required here so street lines ending in things like "Ave NE" can't match
    no_comma_pattern = re.compile(
        r'^(?P<city>.+?)\s+(?P<region>[A-Za-z]{2})[.,]?\s+(?P<zip>\d{5}(?:-\d{4})?)$'
    )

    # Peel explicit country lines (no digits) off the end of the address.
    # A US country line is dropped so the state can still be extracted.
    is_us = False
    while lines:
        last = lines[-1]
        if re.search(r'\d', last):
            break
        country = find_country(last)
        if country is None:
            break
        if country.alpha_2 == 'US':
            is_us = True
            lines.pop()
        else:
            return country_display_name(country)

    # Look for a US state, scanning from the bottom up. Handles "City, ST ZIP",
    # "City, State Name ZIP", "City ST ZIP", a ZIP on its own following line,
    # and truncated "City, ST" addresses (common for digital-goods orders).
    for i in range(len(lines) - 1, -1, -1):
        state = zip_code = city = None
        was_abbrev = False

        match = city_region_pattern.match(lines[i])
        if match:
            state = normalize_us_state(match.group('region'))
            if state:
                zip_code = match.group('zip')
                city = match.group('city').strip()
                was_abbrev = len(match.group('region').replace('.', '').strip()) == 2

        if not state:
            match = no_comma_pattern.match(lines[i])
            if match:
                state = normalize_us_state(match.group('region'))
                if state:
                    zip_code = match.group('zip')
                    city = match.group('city').strip()
                    was_abbrev = True

        if not state:
            continue

        if not zip_code and i + 1 < len(lines):
            next_zip = re.fullmatch(r'\d{5}(?:-\d{4})?', lines[i + 1])
            if next_zip:
                zip_code = next_zip.group(0)

        # A spelled-out region without a ZIP is ambiguous with country names
        # ("Tbilisi, Georgia" must not become GA), so it needs an explicit
        # United States line; a valid two-letter abbreviation is trusted as-is
        # ("Fairview, TX")
        if not zip_code and not is_us and not was_abbrev:
            continue

        if state == 'WA':
            if zip_code:
                return f"{city}, WA {zip_code}"
            return f"{city}, WA" if city else 'WA'
        return state

    # No US state found — look for a country name inside the remaining lines,
    # e.g. "Prague, Czech Republic" on a single line
    for line in reversed(lines):
        country = find_country(line)
        if country is None and ',' in line:
            country = find_country(line.rsplit(',', 1)[-1])
        if country:
            return country_display_name(country)

    return 'United States' if is_us else 'Unknown'

def format_items(line_items):
    formatted_items = []
    for item in line_items:
        if item.quantity > 1:
            formatted_items.append(f"{item.quantity}x {item.product.sku}")
        else:
            formatted_items.append(item.product.sku)
    return '; '.join(formatted_items)

def to_local_naive(value):
    """Normalise a datetime to naive local time.

    Every other write path stores naive local datetimes (ShipStation's dates,
    hand-entered sales). Storing tz-aware UTC alongside them made the sales grid
    sort wrong and could push a sale into the neighbouring quarter on the state
    taxes report.
    """
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone().replace(tzinfo=None)

def process_shipstation_data(shipstation_orders):
    """Turn raw ShipStation order payloads into the shape import_processed_orders wants.

    Pure translation — no database work. It used to call get_or_create_customer
    inside a savepoint and then throw the result away, keeping only the dict.
    """
    processed_orders = []

    for order in shipstation_orders:
        try:
            ship_to = order.get('shipTo') or {}
            customer_data = {
                'name': ship_to.get('name', 'Unknown'),
                'email': order.get('customerEmail'),
                'company': ship_to.get('company', ''),
                'street1': ship_to.get('street1', ''),
                'street2': ship_to.get('street2', ''),
                'street3': ship_to.get('street3', ''),
                'city': ship_to.get('city', ''),
                'state': ship_to.get('state', ''),
                'postal_code': ship_to.get('postalCode', ''),
                'country': ship_to.get('country', ''),
                'phone': ship_to.get('phone', ''),
            }

            processed_orders.append({
                'external_order_id': order['orderId'],
                'external_order_number': order['orderNumber'],
                'order_date': datetime.strptime(
                    parse_shipstation_date(order['orderDate']), '%Y-%m-%dT%H:%M:%S.%f'),
                'customer': customer_data,
                'items': [
                    {
                        'sku': item.get('sku') or 'Unknown SKU',
                        'name': item.get('name') or 'Unknown Item',
                        'quantity': item.get('quantity', 0),
                        'unit_price': Decimal(str(item.get('unitPrice', '0'))),
                    } for item in order.get('items', [])
                ],
                'order_total': Decimal(str(order.get('orderTotal', '0'))),
                'tax_amount': Decimal(str(order.get('taxAmount', '0'))),
                'shipping_amount': Decimal(str(order.get('shippingAmount', '0'))),
                'customer_notes': order.get('customerNotes') or '',
                'internal_notes': order.get('internalNotes') or '',
            })
        except Exception as e:
            app.logger.error(
                f"Skipping malformed ShipStation order {order.get('orderId', 'Unknown')}: {e}")
            continue

    return processed_orders

def process_shippo_data(shippo_orders):
    processed_orders = []
    
    for order in shippo_orders:
        try:
            # Extract customer data from to_address
            to_address = order.get('to_address', {})
            customer_data = {
                'name': to_address.get('name', 'Unknown'),
                'email': to_address.get('email') or order.get('email', ''),
                'company': to_address.get('company', ''),
                'street1': to_address.get('street1', ''),
                'street2': to_address.get('street2', ''),
                'street3': to_address.get('street3', ''),
                'city': to_address.get('city', ''),
                'state': to_address.get('state', ''),
                'postal_code': to_address.get('zip', ''),
                'country': to_address.get('country', ''),
                'phone': to_address.get('phone', ''),
            }
            
            # Parse order date. Shippo returns Z-terminated UTC; convert to naive
            # local time so it sorts and filters alongside every other sale date.
            order_date = order.get('placed_at') or order.get('object_created')
            if order_date:
                if order_date.endswith('Z'):
                    parsed = datetime.strptime(order_date[:-1].split('.')[0], '%Y-%m-%dT%H:%M:%S')
                    order_date = to_local_naive(parsed.replace(tzinfo=timezone.utc))
                else:
                    try:
                        order_date = datetime.strptime(order_date.split('.')[0], '%Y-%m-%dT%H:%M:%S')
                    except ValueError:
                        order_date = datetime.strptime(order_date, '%Y-%m-%d')
            else:
                order_date = datetime.now()
            
            # Process line items
            items = []
            for item in order.get('line_items', []):
                # Handle different price formats
                total_price = item.get('total_price', '0')
                if isinstance(total_price, str):
                    total_price = Decimal(total_price)
                elif isinstance(total_price, (int, float)):
                    total_price = Decimal(str(total_price))
                
                # Calculate unit price from total price and quantity
                quantity = int(item.get('quantity', 1))
                unit_price = total_price / quantity if quantity > 0 else Decimal('0')
                
                items.append({
                    'sku': item.get('sku') or 'Unknown SKU',
                    'name': item.get('title') or 'Unknown Item',
                    'quantity': quantity,
                    'unit_price': unit_price,
                })

            # Extract order totals - handle string/numeric values
            total_price = Decimal(str(order.get('total_price', '0')))
            shipping_cost = Decimal(str(order.get('shipping_cost', '0')))
            total_tax = Decimal(str(order.get('total_tax', '0')))

            shipdate = order_date.date() if order_date else None

            processed_order = {
                'external_order_id': order.get('object_id', ''),
                'external_order_number': order.get('order_number', ''),
                'order_date': order_date,
                # Shippo has no separate ship date; the local order date matches
                # the convention ShipStation imports already use
                'shipdate': shipdate,
                'customer': customer_data,
                'items': items,
                'order_total': total_price,
                'tax_amount': total_tax,
                'shipping_amount': shipping_cost,
                'customer_notes': order.get('notes') or '',
                'internal_notes': f"Imported from {order.get('shop_app', 'Shippo')} via Shippo API"
            }
            
            processed_orders.append(processed_order)
            
        except Exception as e:
            app.logger.error(f"Error processing Shippo order {order.get('order_number', 'Unknown')}: {str(e)}")
            continue
            
    return processed_orders

def parse_shipstation_date(date_str):
    # Split the string at the dot to separate the fractional seconds
    parts = date_str.split('.')
    
    # If there is a fractional part, remove trailing zeros from it
    if len(parts) == 2:
        parts[1] = parts[1].rstrip('0')
        # If the fractional part is empty after stripping, set it to '0'
        fractional_part = parts[1] if parts[1] else '0'
        # Reassemble the string, ensuring the fractional part has at least one digit
        cleaned_date_str = parts[0] + '.' + fractional_part
    else:
        # If there is no fractional part, add '.0' to match the expected format
        cleaned_date_str = parts[0] + '.0'
    
    # Convert to datetime object and return it
    return datetime.strptime(cleaned_date_str, '%Y-%m-%dT%H:%M:%S.%f').strftime('%Y-%m-%dT%H:%M:%S.%f')

def replace_line_items(sale, imported_items):
    """Build a receipt's line items from an imported order.

    Only ever called for receipts the importer just created. Re-importing an
    existing order deliberately leaves its line items alone: the previous code
    deleted and rebuilt them on every fetch, silently discarding prices and
    quantities that had been corrected by hand.
    """
    for item in sale.line_items:
        db.session.delete(item)
    if sale.line_items:
        db.session.flush()

    for item in imported_items:
        product = get_or_create_product(item)
        quantity = int(item['quantity'])
        price_each = Decimal(str(item['unit_price']))
        db.session.add(LineItem(
            receipt_id=sale.id,
            product_id=product.id,
            quantity=quantity,
            price_each=float(price_each),
            total_price=float(price_each * quantity)
        ))
    db.session.flush()

def get_or_create_product(imported_item):
    """Look up a product by SKU on db.session, creating it if it is new.

    The hand-rolled 'database is locked' retry loops this used to carry are gone:
    they caught sqlite3.OperationalError, which SQLAlchemy never raises, and WAL
    journaling plus busy_timeout now handle the contention they were aimed at.
    """
    sku = (imported_item.get('sku') or 'Unknown SKU').strip()[:20]
    product = Product.query.filter_by(sku=sku).first()
    if product:
        return product

    product = Product(
        sku=sku,
        description=(imported_item.get('name') or 'Unknown Item')[:200],
        price=Decimal(str(imported_item.get('unit_price', '0'))),
        # Initial guess from the legacy SKU convention; editable on the products page
        is_manufactured=sku.endswith('A')
    )
    db.session.add(product)
    db.session.flush()
    return product

def merge_customers(customer_id1, customer_id2):
    """
    Merge two customers. The customer with the lower ID is preserved.
    If email addresses differ, the secondary email is saved in email_2 field.
    """
    customer1 = db.session.get(Customer, customer_id1)
    customer2 = db.session.get(Customer, customer_id2)

    if not customer1 or not customer2:
        return False, "One or both customers not found."

    if customer1.id == customer2.id:
        return False, "Cannot merge a customer into itself."

    # Determine which customer to keep (lower ID)
    keep, merge = (customer1, customer2) if customer1.id < customer2.id else (customer2, customer1)

    # Park the other address in email_2, but never overwrite an email_2 that is
    # already in use — that address would be lost with no way to recover it
    dropped_email = None
    if keep.email != merge.email:
        if not keep.email_2:
            keep.email_2 = merge.email
        elif keep.email_2 != merge.email:
            dropped_email = merge.email

    # Merge other fields (use data from 'keep' if available, otherwise use 'merge')
    keep.company = keep.company or merge.company
    keep.phone = keep.phone or merge.phone
    keep.billing_address = keep.billing_address or merge.billing_address
    keep.shipping_address = keep.shipping_address or merge.shipping_address

    # Update foreign keys in related tables
    SalesReceipt.query.filter_by(customer_id=merge.id).update({SalesReceipt.customer_id: keep.id})
    ShipStationCustomerMapping.query.filter_by(customer_id=merge.id).update({ShipStationCustomerMapping.customer_id: keep.id})

    # Delete the merged customer
    db.session.delete(merge)

    try:
        db.session.commit()
        message = f"Customers merged successfully. Kept customer ID: {keep.id}"
        if dropped_email:
            message += (f" Note: {dropped_email} was not kept — "
                        f"both email fields on customer {keep.id} were already in use.")
        return True, message
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error merging customers {customer_id1}/{customer_id2}: {e}")
        return False, f"Error merging customers: {str(e)}"

def is_duplicate_transaction(new_transaction):
    """Check if a transaction already exists in the database"""
    return BankTransaction.query.filter(
        BankTransaction.date == new_transaction.date,
        BankTransaction.description == new_transaction.description,
        BankTransaction.amount == new_transaction.amount,
        BankTransaction.transaction_type == new_transaction.transaction_type,
        BankTransaction.check_number == new_transaction.check_number
    ).first() is not None

# Every platform's fetch/process function now exists, so the registry can be
# built. Import-time, not request-time: the Management page, the dashboard and
# the fetch routes all read it.
build_integration_registry()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # A snapshot on every start, before anyone can touch the data
        backup_database()

    host = os.environ.get('SALES_TRACKER_HOST', '0.0.0.0')  # LAN access is required
    port = int(os.environ.get('SALES_TRACKER_PORT', '4444'))

    try:
        from waitress import serve
    except ImportError:
        app.logger.warning('waitress is not installed; falling back to the Flask dev server. '
                           'Run: pip install -r requirements.txt')
        print('waitress not installed — falling back to the Flask development server.')
        # use_reloader stays off: it runs the whole module twice, so startup
        # backups and db.create_all() would each happen twice per launch
        app.run(debug=False, host=host, port=port, use_reloader=False)
    else:
        app.logger.info(f'Serving with waitress on http://{host}:{port}')
        print(f'Sales Tracker running on http://{host}:{port}  (Ctrl+C to stop)')
        serve(app, host=host, port=port, threads=8, ident='Sales Tracker')