# app.py
import click
from contextlib import contextmanager
import csv
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask.cli import with_appcontext
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import io
import json
import logging
from logging.handlers import RotatingFileHandler
from markupsafe import Markup
import os
import pycountry
import pycountry_convert as pc
import pytz
import random
import re
import requests
import shippo
from shippo import components
from sqlalchemy import and_, create_engine, extract, func
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import joinedload, sessionmaker
from sqlalchemy.pool import QueuePool
import sqlite3
import time
from urllib.parse import urlparse
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Logging Setup
if not os.path.exists('logs'):
    os.makedirs('logs')

handler = RotatingFileHandler('logs/sales_tracker.log', maxBytes=10000000, backupCount=5)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
max_retries = 3
retry_delay = 0.5

# Use environment variable for secret key, with a fallback for development
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24) # disable for testing only

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sales.db?timeout=20'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': QueuePool,
    'pool_size': 10,
    'max_overflow': 20,
    'pool_timeout': 30,
    'pool_recycle': 1800,
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Create a custom engine with a connection pool
#engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], poolclass=QueuePool, **app.config['SQLALCHEMY_ENGINE_OPTIONS'])
Session = db.sessionmaker()

login_manager = LoginManager(app)
login_manager.login_view = 'login'

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

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@contextmanager
def session_scope():
    session = Session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        raise
    finally:
        session.close()

# Retry decorator
def retry_on_db_lock(max_retries=3, delay=0.1):
    def decorator(func):
        @wraps(func)  # This preserves the original function's metadata
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    if "database is locked" in str(e) and attempt < max_retries - 1:
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
    price = db.Column(db.Float, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'sku': self.sku,
            'description': self.description,
            'price': self.price
        }

class SalesReceipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shipstation_order_id = db.Column(db.String(50), unique=True, nullable=True)
    order_number = db.Column(db.String(50), nullable=True)
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
            'id': self.id, # Uniquie identification number
            'shipstation_order_id': self.shipstation_order_id, # ID number generated by Shipstation
            'order_number': self.order_number, # Order number from the marketplace
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
    return Markup(value.replace('\n', '<br>\n'))

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
    recent_sales = SalesReceipt.query.order_by(SalesReceipt.date.desc()).limit(10).all()
    company_info = CompanyInfo.get_info()
    
    # Get integration status
    shippo_credentials = ShippoCredentials.query.first()
    shipstation_credentials = ShipStationCredentials.query.first()
    woocommerce_credentials = WooCommerceCredentials.query.first()
    
    shippo_enabled = shippo_credentials.enabled if shippo_credentials else False
    shipstation_enabled = shipstation_credentials.enabled if shipstation_credentials else False
    woocommerce_enabled = woocommerce_credentials.enabled if woocommerce_credentials else False

    return render_template('index.html', 
                           total_revenue=total_revenue,
                           total_sales=total_sales,
                           total_customers=total_customers,
                           recent_sales=recent_sales,
                           company_info=company_info,
                           shippo_enabled=shippo_enabled,
                           shipstation_enabled=shipstation_enabled,
                           woocommerce_enabled=woocommerce_enabled)

@app.route('/login', methods=['GET', 'POST'])
def login():
    next_page = request.args.get('next')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            # Check if the next parameter is set and is safe to redirect
            if next_page and urlparse(next_page).netloc == '':
                return redirect(next_page)
            else:
                return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
        
    company_info = CompanyInfo.get_info()

    return render_template('login.html', next=next_page, company_info=company_info)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/management', methods=['GET', 'POST'])
@login_required
def management():
    company_info = CompanyInfo.get_info()
    shippo_credentials = ShippoCredentials.query.first()
    shipstation_credentials = ShipStationCredentials.query.first()
    woocommerce_credentials = WooCommerceCredentials.query.first()

    if request.method == 'POST':
        if 'logo' in request.files:
            file = request.files['logo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                logo_path = f'/static/uploads/{filename}'
            else:
                logo_path = company_info.logo if company_info else None
        else:
            logo_path = company_info.logo if company_info else None

        if company_info:
            company_info.name = request.form['name']
            company_info.address = request.form['address']
            company_info.phone = request.form['phone']
            company_info.email = request.form['email']
            company_info.logo = logo_path
        else:
            new_info = CompanyInfo(
                name=request.form['name'],
                address=request.form['address'],
                phone=request.form['phone'],
                email=request.form['email'],
                logo=logo_path
            )
            db.session.add(new_info)

        # Update Shippo credentials
        if shippo_credentials:
            shippo_credentials.api_key = request.form['shippo_api_key']
            shippo_credentials.enabled = 'shippo_enabled' in request.form
        else:
            new_credentials = ShippoCredentials(
                api_key=request.form['shippo_api_key'],
                enabled='shippo_enabled' in request.form
            )
            db.session.add(new_credentials)

        # Update ShipStation credentials
        if shipstation_credentials:
            shipstation_credentials.api_key = request.form['ss_api_key']
            shipstation_credentials.api_secret = request.form['ss_api_secret']
            shipstation_credentials.enabled = 'ss_enabled' in request.form
        else:
            new_credentials = ShipStationCredentials(
                api_key=request.form['ss_api_key'],
                api_secret=request.form['ss_api_secret'],
                enabled='ss_enabled' in request.form
            )
            db.session.add(new_credentials)

        # Update WooCommerce credentials
        if woocommerce_credentials:
            woocommerce_credentials.api_key = request.form['wc_api_key']
            woocommerce_credentials.api_secret = request.form['wc_api_secret']
            woocommerce_credentials.enabled = 'wc_enabled' in request.form
        else:
            new_credentials = WooCommerceCredentials(
                api_key=request.form['wc_api_key'],
                api_secret=request.form['wc_api_secret'],
                enabled='wc_enabled' in request.form
            )
            db.session.add(new_credentials)

        try:
            db.session.commit()
            flash('Settings updated successfully.', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Error updating settings.', 'error')

        return redirect(url_for('management'))

    return render_template('management.html', 
                         company_info=company_info, 
                         shippo_credentials=shippo_credentials, 
                         shipstation_credentials=shipstation_credentials, 
                         woocommerce_credentials=woocommerce_credentials)

@app.route('/state_taxes')
@login_required
def state_taxes():
    sales = SalesReceipt.query.options(joinedload(SalesReceipt.customer)).all()
    sorted_sales = sorted(sales, key=lambda sale: sale.date, reverse=True)

    company_info = CompanyInfo.get_info()
    
    return render_template('state_taxes.html', sales=sorted_sales, company_info=company_info)

@app.route('/api/state_taxes_data')
@login_required
def get_state_taxes_data():
    year = request.args.get('year', type=int)
    quarter = request.args.get('quarter')
    start = request.args.get('start', type=int, default=0)
    end = request.args.get('end', type=int, default=100)

    # Define date ranges for quarters
    date_ranges = {
        'Q1': (f'{year}-01-01 00:00:00', f'{year}-03-31 23:59:59'),
        'Q2': (f'{year}-04-01 00:00:00', f'{year}-06-30 23:59:59'),
        'Q3': (f'{year}-07-01 00:00:00', f'{year}-09-30 23:59:59'),
        'Q4': (f'{year}-10-01 00:00:00', f'{year}-12-31 23:59:59'),
    }

    ''' Save for later to undo if needed
    date_ranges = {
        'Q1': (f'{year}-01-01', f'{year}-03-31'),
        'Q2': (f'{year}-04-01', f'{year}-06-30'),
        'Q3': (f'{year}-07-01', f'{year}-09-30'),
        'Q4': (f'{year}-10-01', f'{year}-12-31'),
    }
    '''

    start_date, end_date = date_ranges.get(quarter, ('', ''))

    # app.logger.info(f"Filtering sales for date range: {start_date} to {end_date}")

    query = SalesReceipt.query.filter(
        SalesReceipt.date.between(start_date, end_date)
    ).options(
        joinedload(SalesReceipt.customer),
        joinedload(SalesReceipt.line_items).joinedload(LineItem.product)
    )

    # Log the actual SQL query being generated
    # app.logger.info(f"Generated SQL: {query.statement.compile(compile_kwargs={'literal_binds': True})}")

     # Log the results count and dates
    # results = query.all()
    # app.logger.info(f"Found {len(results)} results")
    # app.logger.info(f"Date range of results: {min(r.date for r in results)} to {max(r.date for r in results)}")

    total_count = query.count()
    sales = query.offset(start).limit(end - start).all()

    data = []
    for sale in sales:
        manufacturing = sum(item.total_price for item in sale.line_items if item.product.sku.endswith('A'))
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

@app.route('/customers/add', methods=['POST'])
@login_required
def add_customer():
    try:
        data = request.json
        
        #get_or_create_customer(data)  will want to try to swtich to this at some point

        if not data['email']:
            # Generate a unique placeholder email
            placeholder_email = f"placeholder_{uuid.uuid4().hex}@example.com"
            app.logger.warning(f"Missing customer email. Generated placeholder: {placeholder_email}")
            data['email'] = placeholder_email
        
        new_customer = Customer(
            name=data['name'],
            company=data['company'],
            email=data['email'],
            email_2=data['email_2'],
            phone=data['phone'],
            billing_address=data['billing_address'],
            shipping_address=data['shipping_address']
        )
        db.session.add(new_customer)
        db.session.commit()
        
        app.logger.info(f"Successfully added customer {new_customer.name}")
        
        return jsonify({'success': True, 'id': new_customer.id, 'message': f'Customer {new_customer.name} added successfully.', 'category': 'success'}), 200
    except Exception as e:
        db.session.rollback()
        # Hide this error because we have a better error display method through showFlashMessage
        #app.logger.error(f"Error adding customer {new_customer.name}: {str(e)}")
        return jsonify({'success': False, 'message': f'Error adding customer: {str(e)}', 'category': 'error'}), 400

@app.route('/customers/edit/<int:id>', methods=['POST'])
@login_required
def edit_customer(id):
    try:
        customer = Customer.query.get_or_404(id)
        data = request.json
        customer.name = data['name']
        customer.company = data['company']
        customer.email = data['email']
        customer.email_2 = data['email_2']
        customer.phone = data['phone']
        customer.billing_address = data['billing_address']
        customer.shipping_address = data['shipping_address']
        db.session.commit()
        return jsonify({'success': True, 'message': 'Customer updated successfully.', 'category': 'success'}), 200
    except Exception as e:
        db.session.rollback()
        # Hide this error because we have a better error display method through showFlashMessage
        #app.logger.error(f"Error updating customer: {str(e)}")
        return jsonify({'success': False, 'message': f'Error updating customer: {str(e)}', 'category': 'error'}), 400

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
    products = Product.query.all()
    company_info = CompanyInfo.get_info()

    return render_template('products.html', products=products, company_info=company_info)

@app.route('/products/add', methods=['POST'])
@login_required
def add_product():
    data = request.json
    new_product = Product(
        sku=data['sku'],
        description=data['description'],
        price=float(data['price'])  # The price is now a string without the $ sign
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'success': True, 'id': new_product.id})

@app.route('/products/edit/<int:id>', methods=['POST'])
@login_required
def edit_product(id):
    product = Product.query.get_or_404(id)
    data = request.json
    product.sku = data['sku']
    product.description = data['description']
    product.price = float(data['price'])  # The price is now a string without the $ sign
    db.session.commit()
    return jsonify({'success': True})

@app.route('/products/get/<int:id>')
@login_required
def get_product(id):
    product = Product.query.get_or_404(id)
    return jsonify({
        'id': product.id,
        'sku': product.sku,
        'description': product.description,
        'price': float(product.price)  # Send the price as a float
    })

@app.route('/products/delete/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    product = Product.query.get_or_404(id)
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
    return jsonify({
        'id': product.id,
        'sku': product.sku,
        'description': product.description,
        'price': float(product.price)
    })

@app.route('/sales')
@login_required
def sales():
    sales = SalesReceipt.query.options(joinedload(SalesReceipt.customer)).all()
    sorted_sales = sorted(sales, key=lambda sale: sale.date, reverse=True)
    customers = Customer.query.all()
    sorted_customers = sorted(customers, key=lambda customer: customer.name, reverse=False)
    products = Product.query.all()
    sorted_products = sorted(products, key=lambda product: product.sku, reverse=False)
    company_info = CompanyInfo.get_info()

    return render_template('sales.html', sales=sorted_sales, customers=sorted_customers, products=sorted_products, company_info=company_info)

@app.route('/sales/add', methods=['POST'])
@login_required
def add_sale():
    data = request.json

    new_sale = SalesReceipt(
        customer_id=data['customer_id'],
        shipservice=data.get('shipservice', None),
        tracking=data.get('tracking', None),
        shipdate=datetime.strptime(data['shipdate'], '%Y-%m-%d').date() if data.get('shipdate') else None,
        date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
        total=float(data['total']),
        tax=float(data['tax']),
        shipping=float(data['shipping']),
        customer_notes=data.get('customer_notes', ''),
        internal_notes=data.get('internal_notes', ''),
        shipstation_order_id=data.get('shipstation_order_id', '')
    )
    db.session.add(new_sale)
    db.session.flush()
    
    # This assigns an ID to new_sale
    #new_sale.shipstation_order_id = new_sale.id
    new_sale.order_number = new_sale.id

    for item in data['line_items']:
        line_item = LineItem(
            receipt_id=new_sale.id,
            product_id=item['product_id'],
            quantity=int(item['quantity']),
            price_each=float(item['price_each']),
            total_price=float(item['total_price'])
        )
        db.session.add(line_item)

    db.session.commit()
    return jsonify({'success': True, 'id': new_sale.id})

@app.route('/sales/get/<int:id>')
@login_required
def get_sale(id):
    sale = SalesReceipt.query.options(joinedload(SalesReceipt.customer), joinedload(SalesReceipt.line_items)).get_or_404(id)
    return jsonify({
        'id': sale.id,
        'shipstation_order_id': sale.shipstation_order_id, # Used as a generic order ID
        'order_number': sale.order_number,
        'customer_id': sale.customer_id,
        'customer_name': sale.customer.name,
        'customer_email': sale.customer_email,
        'customer_phone': sale.customer_phone,
        'customer_company': sale.customer.company,
        'shipservice': sale.shipservice,
        'tracking': sale.tracking,
        'shipdate': sale.shipdate.strftime('%m-%d-%Y'),
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
            app.logger.info(f"Received POST request to edit sale {id}")
            app.logger.debug(f"Form data: {request.form}")

            # Update sale details
            sale.customer_id = int(request.form['customer_id'])
            sale.shipservice = request.form['shipservice']
            sale.tracking = request.form['tracking']
            sale.shipdate = datetime.strptime(request.form['shipdate'],  '%Y-%m-%d') if request.form['shipdate'] else None
            sale.date = datetime.strptime(request.form['date'], '%Y-%m-%dT%H:%M')
            sale.shipping = Decimal(request.form['shipping'])
            sale.tax = Decimal(request.form['tax'])
            sale.customer_notes = request.form['customer_notes']
            sale.internal_notes = request.form['internal_notes']
            sale.shipstation_order_id = request.form['shipstation_order_id']

            # Handle line items
            # First, remove all existing line items
            for item in sale.line_items:
                db.session.delete(item)
            
            # Now add new line items
            product_ids = request.form.getlist('product_id[]')
            quantities = request.form.getlist('quantity[]')
            prices_each = request.form.getlist('price_each[]')
            
            for product_id, quantity, price_each in zip(product_ids, quantities, prices_each):
                new_line_item = LineItem(
                    receipt_id=sale.id,
                    product_id=int(product_id),
                    quantity=int(quantity),
                    price_each=Decimal(price_each),
                    total_price=Decimal(quantity) * Decimal(price_each)
                )
                db.session.add(new_line_item)

            # Recalculate total
            sale.total = Decimal(request.form['total'])

            app.logger.info(f"Attempting to commit changes for sale {id}")
            db.session.commit()
            app.logger.info(f"Successfully updated sale {id}")
            flash('Sale updated successfully', 'success')
            return redirect(url_for('view_sale', id=sale.id))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating sale {id}: {str(e)}")
            flash(f'Error updating sale: {str(e)}', 'error')

    # For GET requests, render the edit form
    customers = Customer.query.all()
    sorted_customers = sorted(customers, key=lambda customer: customer.name, reverse=False)
    products = Product.query.all()
    sorted_products = sorted(products, key=lambda product: product.sku, reverse=False)
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

    return render_template('view_sale.html', sale=sale, company_info=company_info)

@app.route('/sales/delete/<int:id>', methods=['POST'])
@login_required
def delete_sale(id):
    sale = SalesReceipt.query.get_or_404(id)
    
    # Delete associated line items
    LineItem.query.filter_by(receipt_id=id).delete()
    
    # Delete the sale
    db.session.delete(sale)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/sales/print/<int:id>')
@login_required
def print_sale(id):
    sale = SalesReceipt.query.get_or_404(id)
    company_info = CompanyInfo.get_info()

    return render_template('print_sale.html', sale=sale, company_info=company_info)

@app.route('/api/sales')
@login_required
def get_SalesReceipt():
    # Retrieve all sales receipts sorted by the 'date' field in descending order (newest first).
    SalesReceipts = SalesReceipt.query.order_by(SalesReceipt.date.desc()).all()
    SalesReceipts_dict = [SalesReceipt.to_dict() for SalesReceipt in SalesReceipts]

    return jsonify(SalesReceipts_dict)

''' route without date sorting just in case
@app.route('/api/sales')
@login_required
def get_SalesReceipt():
    SalesReceipts = SalesReceipt.query.all()
    SalesReceipts_dict = [SalesReceipt.to_dict() for SalesReceipt in SalesReceipts]

    return jsonify(SalesReceipts_dict)
'''

@app.route('/api/calculate_tax', methods=['POST'])
@login_required
def calculate_tax():
    total = float(request.json['total'])
    # Assuming a flat 1.5% B&O tax rate for this example
    tax = total * 0.015
    return jsonify({'tax': round(tax, 2)})

@app.route('/shipstation/fetch_orders', methods=['POST'])
@login_required
@retry_on_db_lock()
def fetch_shipstation_orders():
    credentials = ShipStationCredentials.query.first()
    if not credentials:
        return jsonify({'error': 'ShipStation credentials not found'}), 400
    
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    
    if not start_date or not end_date:
        return jsonify({'error': 'Start date and end date are required'}), 400
    
    api_url = 'https://ssapi.shipstation.com/orders'
    
    all_orders = []
    page = 1
    page_size = 500  # Maximum allowed by ShipStation API

    while True:
        params = {
            'orderDateStart': start_date,
            'orderDateEnd': end_date,
            'orderStatus': 'shipped',
            'pageSize': page_size,
            'page': page
        }
        
        try:
            response = requests.get(api_url, params=params, auth=(credentials.api_key, credentials.api_secret))
            response.raise_for_status()
            data = response.json()
            
            orders = data.get('orders', [])
            all_orders.extend(orders)
            
            total_pages = data.get('pages', 1)
            if page >= total_pages:
                break
            
            page += 1
        except requests.RequestException as e:
            app.logger.error(f"Error fetching orders from ShipStation: {str(e)}")
            return jsonify({'error': 'Error fetching orders from ShipStation'}), 500

    orders_created = 0
    orders_updated = 0
    customers_created = 0
    customers_updated = 0
    errors = []

    Session = db.session.session_factory
    session = Session()

    try:
        processed_orders = process_shipstation_data(all_orders)
        
        for order in processed_orders:
            try:
                with session.begin_nested():
                    customer = get_or_create_customer(order['customer'])
                    shipment = fetch_shipstation_shipment(order['order_id'], internal_call=True)
                    
                    serviceCodeParts = shipment['shipments'][0]['serviceCode'].split('_')
                    serviceCodeParts[0] = serviceCodeParts[0].upper()
                    
                    existing_sale = session.query(SalesReceipt).filter_by(
                        order_number=order['order_number']
                        #shipstation_order_id=order['sales_receipt_number'] # TODO: We'll need to update this to match based on the correct item
                    ).first()

                    if existing_sale:
                        existing_sale.shipstation_order_id = order['shipstation_order_id']
                        existing_sale.order_number = order['order_number']
                        existing_sale.shipservice = serviceCodeParts[0]
                        existing_sale.tracking = shipment['shipments'][0]['trackingNumber']
                        existing_sale.shipdate = datetime.strptime(shipment['shipments'][0]['shipDate'], '%Y-%m-%d').date()
                        #existing_sale.customer_id = customer.id
                        #existing_sale.date = order['sales_receipt_date']
                        #existing_sale.total = order['order_total']
                        #existing_sale.tax = order['tax_amount']
                        #existing_sale.shipping = order['shipping_amount']
                        existing_sale.customer_note = order['customer_notes']
                        existing_sale.internal_note = order['internal_notes']
                        orders_updated += 1
                    else:
                        # Create a new sale
                        new_sale = SalesReceipt(
                            customer_id=customer.id,
                            shipstation_order_id=order['shipstation_order_id'],
                            order_number=order['order_number'],
                            shipservice=serviceCodeParts[0],
                            tracking=shipment['shipments'][0]['trackingNumber'],
                            shipdate=datetime.strptime(shipment['shipments'][0]['shipDate'], '%Y-%m-%d').date(),
                            date=order['sales_receipt_date'],
                            total=order['order_total'],
                            tax=order['tax_amount'],
                            shipping=order['shipping_amount'],
                            customer_notes=order['customer_notes'],
                            internal_notes=order['internal_notes']
                        )
                        session.add(new_sale)
                        session.flush()
                        orders_created += 1
                
                # Process line items
                sale = existing_sale or new_sale
                process_line_items(sale, order['items'], session)

            except Exception as e:
                session.rollback()
                error_msg = f"1010: Error processing order {order['order_id']}: {str(e)}"
                app.logger.error(error_msg)
                errors.append(error_msg)
                continue

        session.commit()
        
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

    message = (f'Successfully processed orders. '
               f'Created {orders_created} new orders. '
               f'Updated {orders_updated} existing orders.')
    if errors:
        message += f' Encountered {len(errors)} errors.'
    
    return jsonify({
        'message': message,
        'errors': errors
    }), 200 if not errors else 207

@app.route('/shipstation/fetch_shipment/<int:id>')
@login_required
def fetch_shipstation_shipment(id, internal_call=False):
    credentials = ShipStationCredentials.query.first()
    if not credentials:
        return jsonify({'error': 'ShipStation credentials not found'}), 400
    
    orderId = id
    
    if not orderId:
        return jsonify({'error': 'Order IDs are required'}), 400
    
    api_url = 'https://ssapi.shipstation.com/shipments'

    while True:
        params = {
            'orderId': orderId,
            'includeShipmentItems': True
        }
        
        try:
            response = requests.get(api_url, params=params, auth=(credentials.api_key, credentials.api_secret))
            response.raise_for_status()
            shipments = response.json()
            
            #shipments = data.get('shipments', [])
            return (jsonify(shipments), 200) if not internal_call else (shipments)
            
        except requests.RequestException as e:
            app.logger.error(f"Error fetching shipments from ShipStation: {str(e)}")
            return jsonify({'error': 'Error fetching shipments from ShipStation'}), 500

@app.route('/shipstation/update_shipment/<int:id>')
@login_required
def update_shipment(id):
    credentials = ShipStationCredentials.query.first()
    if not credentials:
        return jsonify({'error': 'ShipStation credentials not found'}), 400
    
    orderId = id
    errors = []
    
    # Call the function to update just the notes since it uses a different URL but we want to update everything at the same time
    update_notes(orderId)

    if not orderId:
        return jsonify({'error': 'Order IDs are required'}), 400
    
    api_url = 'https://ssapi.shipstation.com/shipments'

    params = {
        'orderId': orderId,
        'includeShipmentItems': True
    }
    
    try:
        response = requests.get(api_url, params=params, auth=(credentials.api_key, credentials.api_secret))
        response.raise_for_status()
        shipments = response.json()
        if not shipments.get('shipments'):
            return view_sale(id), 404

    except requests.RequestException as e:
        app.logger.error(f"Error fetching shipments from ShipStation: {str(e)}")
        return jsonify({'error': 'Error fetching shipments from ShipStation'}), 500
    
    try:
        with db.session.begin_nested():           
            # Split serviceCode into parts so we can get the carrier only
            serviceCodeParts = shipments['shipments'][0]['serviceCode'].split('_')
            # Capitalize the first part
            serviceCodeParts[0] = serviceCodeParts[0].upper()
            sale = SalesReceipt.query.filter_by(id=id).first()

            # Update sale
            sale.shipservice = serviceCodeParts[0]
            sale.tracking = shipments['shipments'][0]['trackingNumber']
            sale.shipdate = datetime.strptime(shipments['shipments'][0]['shipDate'], '%Y-%m-%d').date()
            sale.shipstation_order_id = shipments['shipments'][0]['orderId']
            sale.order_number = shipments['shipments'][0]['orderNumber']

    except Exception as e:
        db.session.rollback()
        error_msg = f"1117: Error processing order {id}: {str(e)}"
        app.logger.error(error_msg)
        errors.append(error_msg)

    try:
        db.session.commit()
        message = (f'Successfully updated order {id}.')
        if errors:
            message += f' Encountered {len(errors)} errors.'
        
        app.logger.info(message)
        return view_sale(id), 200 if not errors else 207  # Use 207 Multi-Status if there were some errors
    
    except IntegrityError as e:
        db.session.rollback()
        error_msg = f'Error committing changes to database: {str(e)}'
        app.logger.error(error_msg)
        return jsonify({'error': error_msg}), 500

@app.route('/shipstation/update_notes/<int:id>')
@login_required
def update_notes(id):
    credentials = ShipStationCredentials.query.first()
    if not credentials:
        return jsonify({'error': 'ShipStation credentials not found'}), 400
    
    orderId = SalesReceipt.query.filter_by(id=id).first().shipstation_order_id
    errors = []
    
    if not orderId:
        return jsonify({'error': 'Order IDs are required'}), 400
    
    api_url = f'https://ssapi.shipstation.com/orders/{orderId}'
    
    try:
        response = requests.get(api_url, auth=(credentials.api_key, credentials.api_secret))
        response.raise_for_status()
        orders = response.json()
        if not orders.get('orderId'):
            return view_sale(id), 404

    except requests.RequestException as e:
        app.logger.error(f"Error fetching order info from ShipStation: {str(e)}")
        return jsonify({'error': 'Error fetching order info from ShipStation'}), 500
    
    try:
        with db.session.begin_nested():           
            sale = SalesReceipt.query.filter_by(id=id).first()
            
            # Update sale
            
            # Existing notes
            existing_customer_notes = sale.customer_notes or ""
            existing_internal_notes = sale.internal_notes or ""

            # New notes from ShipStation
            new_customer_notes = orders.get("customerNotes", "")
            new_internal_notes = orders.get("internalNotes", "")

            # For customer notes:
            # 1. Check if new_customer_notes is not empty
            # 2. Check if existing_customer_notes does not contain the new_customer_notes
            # 3. Append if needed
            if new_customer_notes and new_customer_notes not in existing_customer_notes:
                if existing_customer_notes:
                    sale.customer_notes = existing_customer_notes + "\n" + new_customer_notes
                else:
                    sale.customer_notes = new_customer_notes

            # For internal notes, do the same checks
            if new_internal_notes and new_internal_notes not in existing_internal_notes:
                if existing_internal_notes:
                    sale.internal_notes = existing_internal_notes + "\n" + new_internal_notes
                else:
                    sale.internal_notes = new_internal_notes

    except Exception as e:
        db.session.rollback()
        error_msg = f"1195: Error processing order {id}: {str(e)}"
        app.logger.error(error_msg)
        errors.append(error_msg)

    try:
        db.session.commit()
        message = (f'Successfully updated order {id}.')
        if errors:
            message += f' Encountered {len(errors)} errors.'
        
        app.logger.info(message)
        return view_sale(id), 200 if not errors else 207  # Use 207 Multi-Status if there were some errors
    
    except IntegrityError as e:
        db.session.rollback()
        error_msg = f'Error committing changes to database: {str(e)}'
        app.logger.error(error_msg)
        return jsonify({'error': error_msg}), 500

@app.route('/shippo/fetch_orders', methods=['POST'])
@login_required
@retry_on_db_lock()
def fetch_shippo_orders():
    credentials = ShippoCredentials.query.first()
    if not credentials:
        return jsonify({'error': 'Shippo credentials not found'}), 400
    
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    
    if not start_date or not end_date:
        return jsonify({'error': 'Start date and end date are required'}), 400
    
    # Convert dates to correct format for Shippo API
    try:
        start_dt = datetime.strptime(start_date, '%Y-%m-%d')
        end_dt = datetime.strptime(end_date, '%Y-%m-%d')
        # Format as required by Shippo API (YYYY-MM-DDTHH:MM:SS)
        start_formatted = start_dt.strftime('%Y-%m-%dT00:00:00')
        end_formatted = end_dt.strftime('%Y-%m-%dT23:59:59')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
    
    api_url = 'https://api.goshippo.com/orders'
    
    all_orders = []
    page = 1
    results_per_page = 25  # Shippo default is 25
    
    headers = {
        'Authorization': f'ShippoToken {credentials.api_key}',
        'Content-Type': 'application/json'
    }

    while True:
        # Use correct Shippo API parameters
        params = {
            'results': results_per_page,
            'page': page,
            'start_date': start_formatted,
            'end_date': end_formatted,
            'order_status[]': 'SHIPPED'  # Correct array notation
        }
        
        try:
            response = requests.get(api_url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

            app.logger.info(f"API URL: {api_url}")
            app.logger.info(f"API params: {params}")
            app.logger.info(f"Response status: {response.status_code}")
            app.logger.info(f"Response content: {data}")
            
            orders = data.get('results', [])
            all_orders.extend(orders)
            
            # Check if there are more pages
            if not data.get('next'):
                break
                
            page += 1
        except requests.RequestException as e:
            app.logger.error(f"Error fetching orders from Shippo: {str(e)}")
            return jsonify({'error': 'Error fetching orders from Shippo'}), 500

    # If still no orders, try a broader search without filters
    if not all_orders:
        app.logger.info("No orders found with filters, trying without date/status filters...")
        try:
            params_simple = {
                'results': 25,
                'page': 1
            }
            response = requests.get(api_url, params=params_simple, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            app.logger.info(f"Simple query results: {data}")
            
            if not data.get('results'):
                return jsonify({
                    'message': 'No orders found in Shippo. Orders are typically created when you generate shipping labels or connect an e-commerce platform.',
                    'suggestion': 'Try creating a test order first or check if your e-commerce platform is connected.'
                })
                
        except requests.RequestException as e:
            app.logger.error(f"Error in simple query: {str(e)}")

    orders_created = 0
    orders_updated = 0
    errors = []

    Session = db.session.session_factory
    session = Session()

    try:
        processed_orders = process_shippo_data(all_orders)
        
        for order in processed_orders:
            try:
                with session.begin_nested():
                    customer = get_or_create_customer(order['customer'])
                    
                    existing_sale = session.query(SalesReceipt).filter_by(
                        order_number=order['order_number']
                    ).first()

                    if existing_sale:
                        existing_sale.customer_id = customer.id
                        existing_sale.date = order['order_date']
                        existing_sale.total = order['order_total']
                        existing_sale.tax = order['tax_amount']
                        existing_sale.shipping = order['shipping_amount']
                        existing_sale.customer_notes = order.get('customer_notes', '')
                        existing_sale.internal_notes = order.get('internal_notes', '')
                        orders_updated += 1
                    else:
                        new_sale = SalesReceipt(
                            customer_id=customer.id,
                            shipstation_order_id=order['order_id'],
                            order_number=order['order_number'],
                            date=order['order_date'],
                            total=order['order_total'],
                            tax=order['tax_amount'],
                            shipping=order['shipping_amount'],
                            customer_notes=order.get('customer_notes', ''),
                            internal_notes=order.get('internal_notes', '')
                        )
                        session.add(new_sale)
                        session.flush()
                        orders_created += 1
                
                # Process line items
                sale = existing_sale or new_sale
                process_line_items(sale, order['items'], session)

            except Exception as e:
                session.rollback()
                error_msg = f"Error processing order {order['order_number']}: {str(e)}"
                app.logger.error(error_msg)
                errors.append(error_msg)
                continue

        session.commit()
        
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

    message = (f'Successfully processed Shippo orders. '
               f'Created {orders_created} new orders. '
               f'Updated {orders_updated} existing orders.')
    if errors:
        message += f' Encountered {len(errors)} errors.'
    
    return jsonify({
        'message': message,
        'errors': errors
    }), 200 if not errors else 207

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
                except ValueError as e:
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
        receipt = SalesReceipt.query.get_or_404(receipt_id)
        
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
    
    for attempt in range(max_retries):
        try:
            with db.session.no_autoflush:
                email = customer_data.get('email')
                
                if not email:
                    placeholder_email = f"placeholder_{uuid.uuid4().hex}@example.com"
                    app.logger.warning(f"Missing customer email. Generated placeholder: {placeholder_email}")
                    email = placeholder_email

                customer = Customer.query.filter_by(email=email).first()
    
                if not customer:
                    formatted_name = format_name(customer_data.get('name', 'Unknown'))
                    customer = Customer(
                        name=formatted_name,
                        company=customer_data.get('company', ''),
                        email=email,
                        phone=customer_data.get('phone', ''),
                        billing_address=format_address(customer_data),
                        shipping_address=format_address(customer_data)
                    )
                    db.session.add(customer)
                    db.session.flush()
                #else:
                #    # Update existing customer information
                #    customer.name = formatted_name
                #    customer.company = customer_data.get('company', customer.company)
                #    customer.phone = customer_data.get('phone', customer.phone)
                #    customer.billing_address = format_address(customer_data)
                #    customer.shipping_address = format_address(customer_data)

                return customer

        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
            else:
                raise
        
    raise Exception("Failed to create/get customer after retries")

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

    # Combine the address parts with proper capitalization
    address_parts = [
        title_capitalize(address_dict.get('street1', '')),
        title_capitalize(address_dict.get('street2', '')),
        title_capitalize(address_dict.get('street3', '')),
        f"{title_capitalize(address_dict.get('city', ''))}, {state_full} {address_dict.get('postal_code', '')}",
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
    subdivisions = pycountry.subdivisions.get(country_code=country_code)
    for subdivision in subdivisions:
        if subdivision.code.split('-')[-1] == state_code:
            return subdivision.name
    return state_code

def get_state_info(address):
    #print(f"Processing address: {address}")  # Debug print
    
    address_parts = address.split('\n')
    if len(address_parts) < 2:
        #print("Address has fewer than 2 lines, returning 'Unknown'")  # Debug print
        return 'Unknown'

    # Check if the last line is a country
    potential_country = address_parts[-1].strip()
    
    # Special case for Czech Republic because pycountry expects Czechia
    if potential_country == 'Czech Republic':
        return 'Czech Republic'

    country = pycountry.countries.get(name=potential_country)
    if country:
        #print(f"Non-US address detected, country: {country.name}")  # Debug print
        return country.name

    # For US addresses, we need to handle both combined and split state/zip formats
    for i in range(len(address_parts) - 1):
        line = address_parts[i].strip()
        us_state_pattern = r',\s*(\w{2})\s*$'  # Matches ", XX" at end of line
        state_match = re.search(us_state_pattern, line)
        
        if state_match:
            state = state_match.group(1)
            # Check if next line contains a ZIP code
            next_line = address_parts[i + 1].strip()
            zip_pattern = r'^\d{5}(-\d{4})?$'
            if re.match(zip_pattern, next_line):
                if state == 'WA':
                    # For Washington, return City, State, ZIP
                    city_match = re.match(r'^(.+),', state_country_line)
                    city = city_match.group(1) if city_match else 'Unknown City'
                    zip_match = re.search(r'(\d{5}(-\d{4})?)$', state_country_line)
                    zip_code = zip_match.group(1) if zip_match else 'Unknown ZIP'
                    return f"{city}, WA {zip_code}"
                return state

    # For US addresses, the state info should be in the last line
    state_country_line = address_parts[-1].strip()
    #print(f"State/country line: {state_country_line}")  # Debug print

    # US address pattern: City, State ZIP
    us_pattern = r',\s*(\w{2})\s+\d{5}(-\d{4})?$'
    us_match = re.search(us_pattern, state_country_line)

    if us_match:
        state = us_match.group(1)
        if state == 'WA':
            # For Washington, return City, State, ZIP
            city_match = re.match(r'^(.+),', state_country_line)
            city = city_match.group(1) if city_match else 'Unknown City'
            zip_match = re.search(r'(\d{5}(-\d{4})?)$', state_country_line)
            zip_code = zip_match.group(1) if zip_match else 'Unknown ZIP'
            result = f"{city}, WA {zip_code}"
        else:
            result = state
    else:
        # If it doesn't match US pattern, check each line for a country name
        for line in reversed(address_parts):
            country = pycountry.countries.get(name=line.strip())
            if country:
                result = country.name
                break

            # Try to find country name within the line
            # This helps with lines like "Prague, Czech Republic"
            words = line.split()
            for i in range(len(words)):
                for j in range(i + 1, len(words) + 1):
                    potential_country = ' '.join(words[i:j])
                    country = pycountry.countries.get(name=potential_country)
                    if country:
                        return country.name
        else:
            result = 'Unknown'

    #print(f"Extracted result: {result}")  # Debug print
    return result

def format_items(line_items):
    formatted_items = []
    for item in line_items:
        if item.quantity > 1:
            formatted_items.append(f"{item.quantity}x {item.product.sku}")
        else:
            formatted_items.append(item.product.sku)
    return '; '.join(formatted_items)

def process_shipstation_data(shipstation_orders):
    processed_orders = []

    for order in shipstation_orders:
        try:
            # Use a dedicated session for each order
            with db.session.begin_nested() as nested:
                try:
                    customer_data = {
                        'name': order['shipTo'].get('name', 'Unknown'),
                        'email': order.get('customerEmail'),
                        'company': order['shipTo'].get('company', ''),
                        'street1': order['shipTo'].get('street1', ''),
                        'street2': order['shipTo'].get('street2', ''),
                        'street3': order['shipTo'].get('street3', ''),
                        'city': order['shipTo'].get('city', ''),
                        'state': order['shipTo'].get('state', ''),
                        'postal_code': order['shipTo'].get('postalCode', ''),
                        'country': order['shipTo'].get('country', ''),
                        'phone': order['shipTo'].get('phone', ''),
                    }

                    # Use get_or_create_customer with retry logic                  
                    for attempt in range(max_retries):
                        try:
                            customer = get_or_create_customer(customer_data)
                            break
                        except sqlite3.OperationalError as e:
                            if "database is locked" in str(e) and attempt < max_retries - 1:
                                time.sleep(retry_delay * (2 ** attempt))
                            else:
                                raise

                    if not customer:
                        raise Exception("Failed to create/get customer after retries")

                    processed_order = {
                        'order_id': order['orderId'],
                        'shipstation_order_id': order['orderId'],
                        'order_number': order['orderNumber'],
                        'sales_receipt_date': datetime.strptime(parse_shipstation_date(order['orderDate']), '%Y-%m-%dT%H:%M:%S.%f'),
                        'customer': customer_data,  # Use the original customer_data dictionary
                        'items': [
                            {
                                'sku': item.get('sku', 'Unknown SKU'),
                                'name': item.get('name', 'Unknown Item'),
                                'quantity': item.get('quantity', 0),
                                'unit_price': Decimal(str(item.get('unitPrice', '0'))),
                                'options': item.get('options', []),
                            } for item in order.get('items', [])
                        ],
                        'order_total': Decimal(str(order.get('orderTotal', '0'))),
                        'amount_paid': Decimal(str(order.get('amountPaid', '0'))),
                        'tax_amount': Decimal(str(order.get('taxAmount', '0'))),
                        'shipping_amount': Decimal(str(order.get('shippingAmount', '0'))),
                        'customer_notes': order['customerNotes'],
                        'internal_notes': order['internalNotes']
                    }
                    processed_orders.append(processed_order)

                except Exception as e:
                    nested.rollback()
                    raise e

        except Exception as e:
            app.logger.error(f"1608: Error processing order {order.get('orderId', 'Unknown')}: {str(e)}")
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
            
            # Parse order date - fix for Shippo's Z-terminated dates
            order_date = order.get('placed_at') or order.get('object_created')
            if order_date:
                # Handle Z-terminated UTC dates from Shippo
                if order_date.endswith('Z'):
                    # Remove Z and parse as UTC
                    order_date = datetime.strptime(order_date[:-1], '%Y-%m-%dT%H:%M:%S')
                    order_date = order_date.replace(tzinfo=timezone.utc)
                else:
                    # Try other common formats
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
                    'sku': item.get('sku', 'Unknown SKU'),
                    'name': item.get('title', 'Unknown Item'),
                    'quantity': quantity,
                    'unit_price': unit_price,
                    'options': []
                })
            
            # Extract order totals - handle string/numeric values
            total_price = Decimal(str(order.get('total_price', '0')))
            shipping_cost = Decimal(str(order.get('shipping_cost', '0')))
            total_tax = Decimal(str(order.get('total_tax', '0')))
            
            processed_order = {
                'order_id': order.get('object_id', ''),
                'order_number': order.get('order_number', ''),
                'order_date': order_date,
                'customer': customer_data,
                'items': items,
                'order_total': total_price,
                'tax_amount': total_tax,
                'shipping_amount': shipping_cost,
                'customer_notes': order.get('notes', ''),
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

def process_line_items(sale, shipstation_items, session):
    try:
        # Use a nested transaction for deleting line items
        with session.begin_nested():
            # Delete existing line items if updating an existing sale
            if sale.line_items:
                for item in sale.line_items:
                    session.delete(item)
                session.flush()  # Flush the deletes first
            
            # Create new line items
            for item in shipstation_items:
                product = get_or_create_product(item, session)
                line_item = LineItem(
                    receipt_id=sale.id,
                    product_id=product.id,
                    quantity=int(item['quantity']),
                    price_each=float(item['unit_price']),
                    total_price=float(item['quantity']) * float(item['unit_price'])
                )
                session.add(line_item)
                
            session.flush()  # Flush the new items
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            # Implement retry logic
            for attempt in range(3):
                try:
                    time.sleep(0.5 * (2 ** attempt))
                    # Retry the entire operation
                    with session.begin_nested():
                        if sale.line_items:
                            for item in sale.line_items:
                                session.delete(item)
                            session.flush()
                        
                        for item in shipstation_items:
                            product = get_or_create_product(item, session)
                            line_item = LineItem(
                                receipt_id=sale.id,
                                product_id=product.id,
                                quantity=int(item['quantity']),
                                price_each=float(item['unit_price']),
                                total_price=float(item['quantity']) * float(item['unit_price'])
                            )
                            session.add(line_item)
                            
                        session.flush()
                    break
                except sqlite3.OperationalError:
                    if attempt == 2:  # Last attempt
                        raise
                    continue
        else:
            raise

def get_or_create_product(shipstation_item, session):
    """Get or create a product with the given session"""
    try:
        with session.begin_nested():
            product = session.query(Product).filter_by(sku=shipstation_item['sku']).first()
            if not product:
                product = Product(
                    sku=shipstation_item['sku'],
                    description=shipstation_item['name'],
                    price=float(shipstation_item['unit_price'])
                )
                session.add(product)
                session.flush()
            return product
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            for attempt in range(3):
                try:
                    time.sleep(0.5 * (2 ** attempt))
                    with session.begin_nested():
                        product = session.query(Product).filter_by(sku=shipstation_item['sku']).first()
                        if not product:
                            product = Product(
                                sku=shipstation_item['sku'],
                                description=shipstation_item['name'],
                                price=float(shipstation_item['unit_price'])
                            )
                            session.add(product)
                            session.flush()
                        return product
                except sqlite3.OperationalError:
                    if attempt == 2:  # Last attempt
                        raise
                    continue
        raise

def merge_customers(customer_id1, customer_id2):
    """
    Merge two customers. The customer with the lower ID is preserved.
    If email addresses differ, the secondary email is saved in email_2 field.
    """
    customer1 = Customer.query.get(customer_id1)
    customer2 = Customer.query.get(customer_id2)

    if not customer1 or not customer2:
        return False, "One or both customers not found."

    # Determine which customer to keep (lower ID)
    keep, merge = (customer1, customer2) if customer1.id < customer2.id else (customer2, customer1)

    # Merge email if different
    if keep.email != merge.email:
        keep.email_2 = merge.email

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
        return True, f"Customers merged successfully. Kept customer ID: {keep.id}"
    except SQLAlchemyError as e:
        db.session.rollback()
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host="0.0.0.0", port=4444, use_reloader=True)