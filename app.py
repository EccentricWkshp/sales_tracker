# app.py
import click
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask.cli import with_appcontext
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import logging
from markupsafe import Markup
import os
import pytz
import requests
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import joinedload
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Use environment variable for secret key, with a fallback for development
app.config['SECRET_KEY'] = 'SECRETKEY' #os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sales.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
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

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    billing_address = db.Column(db.String(200), nullable=False)
    shipping_address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    sales = db.relationship('SalesReceipt', backref='customer', lazy=True)
    shipstation_mapping = db.relationship('ShipStationCustomerMapping', uselist=False, back_populates='customer')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)

class SalesReceipt(db.Model):
    shipstation_order_id = db.Column(db.String(50))  # Add the new column here
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    total = db.Column(db.Float, nullable=False)
    tax = db.Column(db.Float, nullable=False)
    shipping = db.Column(db.Float, nullable=False)
    shipstation_order_id = db.Column(db.String(50), unique=True, nullable=True)
    line_items = db.relationship('LineItem', backref='sales_receipt', lazy=True)

class LineItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_id = db.Column(db.Integer, db.ForeignKey('sales_receipt.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_each = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    product = db.relationship('Product')

class ShipStationCustomerMapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    shipstation_customer_id = db.Column(db.String(50), unique=True, nullable=False)
    customer = db.relationship('Customer', back_populates='shipstation_mapping')

class ShipStationCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(100), nullable=False)
    api_secret = db.Column(db.String(100), nullable=False)

@app.template_filter('nl2br')
def nl2br(value):
    return Markup(value.replace('\n', '<br>\n'))

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
    recent_sales = SalesReceipt.query.order_by(SalesReceipt.date.desc()).limit(5).all()

    return render_template('index.html',
                           total_revenue=total_revenue,
                           total_sales=total_sales,
                           total_customers=total_customers,
                           recent_sales=recent_sales)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/customers')
@login_required
def customers():
    customers = Customer.query.all()
    return render_template('customers.html', customers=customers)

@app.route('/customers/add', methods=['POST'])
@login_required
def add_customer():
    data = request.json
    new_customer = Customer(
        name=data['name'],
        email=data['email'],
        billing_address=data['billing_address'],
        shipping_address=data['shipping_address']
    )
    db.session.add(new_customer)
    db.session.commit()
    return jsonify({'success': True, 'id': new_customer.id})

@app.route('/customers/edit/<int:id>', methods=['POST'])
@login_required
def edit_customer(id):
    customer = Customer.query.get_or_404(id)
    data = request.json
    customer.name = data['name']
    customer.email = data['email']
    customer.billing_address = data['billing_address']
    customer.shipping_address = data['shipping_address']
    db.session.commit()
    return jsonify({'success': True})

@app.route('/customers/get/<int:id>')
@login_required
def get_customer(id):
    customer = Customer.query.get_or_404(id)
    return jsonify({
        'id': customer.id,
        'name': customer.name,
        'email': customer.email,
        'billing_address': customer.billing_address,
        'shipping_address': customer.shipping_address
    })

@app.route('/customers/delete/<int:id>', methods=['POST'])
@login_required
def delete_customer(id):
    customer = Customer.query.get_or_404(id)
    db.session.delete(customer)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/products')
@login_required
def products():
    products = Product.query.all()
    return render_template('products.html', products=products)

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

@app.route('/sales')
@login_required
def sales():
    sales = SalesReceipt.query.options(joinedload(SalesReceipt.customer)).all()
    customers = Customer.query.all()
    products = Product.query.all()
    return render_template('sales.html', sales=sales, customers=customers, products=products)

@app.route('/sales/add', methods=['POST'])
@login_required
def add_sale():
    data = request.json
    new_sale = SalesReceipt(
        customer_id=data['customer_id'],
        date=datetime.utcnow(),
        total=float(data['total']),
        tax=float(data['tax']),
        shipping=float(data['shipping'])
    )
    db.session.add(new_sale)
    db.session.flush()  # This assigns an ID to new_sale

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
        'customer_id': sale.customer_id,
        'customer_name': sale.customer.name,
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
        } for item in sale.line_items]
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
            sale.date = datetime.strptime(request.form['date'], '%Y-%m-%dT%H:%M')
            sale.shipping = Decimal(request.form['shipping'])
            sale.tax = Decimal(request.form['tax'])

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
    products = Product.query.all()
    return render_template('edit_sale.html', sale=sale, customers=customers, products=products)

@app.route('/sales/view/<int:id>')
@login_required
def view_sale(id):
    sale = SalesReceipt.query.options(
        joinedload(SalesReceipt.customer),
        joinedload(SalesReceipt.line_items).joinedload(LineItem.product)
    ).get_or_404(id)
    return render_template('view_sale.html', sale=sale)

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

@app.route('/api/calculate_tax', methods=['POST'])
@login_required
def calculate_tax():
    total = float(request.json['total'])
    # Assuming a flat 1.5% B&O tax rate for this example
    tax = total * 0.015
    return jsonify({'tax': round(tax, 2)})

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

@app.route('/shipstation/credentials', methods=['GET', 'POST'])
@login_required
def shipstation_credentials():
    if request.method == 'POST':
        api_key = request.form['api_key']
        api_secret = request.form['api_secret']
        
        credentials = ShipStationCredentials.query.first()
        if credentials:
            credentials.api_key = api_key
            credentials.api_secret = api_secret
        else:
            credentials = ShipStationCredentials(api_key=api_key, api_secret=api_secret)
            db.session.add(credentials)
        
        try:
            db.session.commit()
            flash('ShipStation credentials updated successfully.', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Error updating ShipStation credentials.', 'error')
        
        return redirect(url_for('shipstation_credentials'))
    
    credentials = ShipStationCredentials.query.first()
    return render_template('shipstation_credentials.html', credentials=credentials)

@app.route('/shipstation/fetch_orders', methods=['POST'])
@login_required
def fetch_shipstation_orders():
    credentials = ShipStationCredentials.query.first()
    if not credentials:
        return jsonify({'error': 'ShipStation credentials not found'}), 400
    
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    
    if not start_date or not end_date:
        return jsonify({'error': 'Start date and end date are required'}), 400
    
    api_url = 'https://ssapi.shipstation.com/orders'
    params = {
        'orderDateStart': start_date,
        'orderDateEnd': end_date,
        'orderStatus': 'shipped'
    }
    
    try:
        response = requests.get(api_url, params=params, auth=(credentials.api_key, credentials.api_secret))
        response.raise_for_status()
    except requests.RequestException as e:
        app.logger.error(f"Error fetching orders from ShipStation: {str(e)}")
        return jsonify({'error': 'Error fetching orders from ShipStation'}), 500
    
    shipstation_orders = response.json()
    
    processed_orders = process_shipstation_data(shipstation_orders.get('orders', []))
    
    orders_created = 0
    orders_updated = 0
    customers_created = 0
    errors = []

    for order in processed_orders:
        try:
            customer = get_or_create_customer(order['customer'])
            if customer.id is None:
                customers_created += 1

            existing_sale = SalesReceipt.query.filter_by(id=order['sales_receipt_number']).first()
            
            if existing_sale:
                # Update existing sale
                existing_sale.customer_id = customer.id
                existing_sale.date = order['sales_receipt_date']
                existing_sale.total = order['order_total']
                existing_sale.tax = order['tax_amount']
                existing_sale.shipping = order['shipping_amount']
                orders_updated += 1
            else:
                # Create a new sale
                new_sale = SalesReceipt(
                    customer_id=customer.id,
                    date=order['sales_receipt_date'],
                    total=order['order_total'],
                    tax=order['tax_amount'],
                    shipping=order['shipping_amount'],
                    id=order['sales_receipt_number']
                )
                db.session.add(new_sale)
                orders_created += 1
            
            # Process line items
            sale = existing_sale or new_sale
            process_line_items(sale, order['items'])

        except Exception as e:
            db.session.rollback()
            error_msg = f"Error processing order {order['sales_receipt_number']}: {str(e)}"
            app.logger.error(error_msg)
            errors.append(error_msg)
            continue

    try:
        db.session.commit()
        message = (f'Successfully processed {len(processed_orders)} orders from ShipStation. '
                   f'Created {orders_created} new orders, updated {orders_updated} existing orders, '
                   f'and added {customers_created} new customers.')
        if errors:
            message += f' Encountered {len(errors)} errors.'
        
        app.logger.info(message)
        return jsonify({
            'message': message,
            'errors': errors
        }), 200 if not errors else 207  # Use 207 Multi-Status if there were some errors
    except IntegrityError as e:
        db.session.rollback()
        error_msg = f'Error committing changes to database: {str(e)}'
        app.logger.error(error_msg)
        return jsonify({'error': error_msg}), 500

def get_or_create_customer(customer_data):
    customer = Customer.query.filter_by(email=customer_data['name']).first()
    if not customer:
        customer = Customer(
            name=customer_data['name'],
            email=customer_data['name'],  # Using name as email as a fallback
            phone=customer_data['phone'],
            billing_address=format_address(customer_data),
            shipping_address=format_address(customer_data)
        )
        db.session.add(customer)
    return customer

def format_address(address_dict):
    return f"{address_dict['name']}, " \
           f"{address_dict['street1']}, " \
           f"{address_dict['street2']}, " \
           f"{address_dict['street3']}, " \
           f"{address_dict['city']}, " \
           f"{address_dict['state']} " \
           f"{address_dict['postal_code']}, " \
           f"{address_dict['country']}".replace(', ,', ',').strip(', ')

def process_shipstation_data(shipstation_orders):
    processed_orders = []

    for order in shipstation_orders:
        app.logger.error(f"order date: {order['orderDate']}")

        #ship_date = datetime.strptime(order['shipDate'], '%Y-%m-%dT%H:%M:%S.%f')

        #if sales_receipt_date is None or ship_date is None:
        #    app.logger.error(f"Skipping order {order['orderNumber']} due to invalid date")
        #    continue

        processed_order = {
            'sales_receipt_number': order['orderNumber'],
            'sales_receipt_date': datetime.strptime(parse_shipstation_date(order['orderDate']), '%Y-%m-%dT%H:%M:%S.%f'),
            #'ship_date': parse_shipstation_date(order['shipDate']),
            'customer': {
                'name': order['shipTo']['name'],
                'company': order['shipTo'].get('company', ''),
                'street1': order['shipTo']['street1'],
                'street2': order['shipTo'].get('street2', ''),
                'street3': order['shipTo'].get('street3', ''),
                'city': order['shipTo']['city'],
                'state': order['shipTo']['state'],
                'postal_code': order['shipTo']['postalCode'],
                'country': order['shipTo']['country'],
                'phone': order['shipTo']['phone'],
            },
            'items': [
                {
                    'sku': item['sku'],
                    'name': item['name'],
                    'quantity': item['quantity'],
                    'unit_price': Decimal(str(item['unitPrice'])),
                    'options': item['options'],
                } for item in order['items']
            ],
            'order_total': Decimal(str(order['orderTotal'])),
            'amount_paid': Decimal(str(order['amountPaid'])),
            'tax_amount': Decimal(str(order['taxAmount'])),
            'shipping_amount': Decimal(str(order['shippingAmount'])),
        }
        processed_orders.append(processed_order)

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

def process_line_items(sale, shipstation_items):
    # Remove existing line items if updating an existing sale
    if sale.line_items:
        for item in sale.line_items:
            db.session.delete(item)
        sale.line_items = []

    for item in shipstation_items:
        product = get_or_create_product(item)
        line_item = LineItem(
            receipt_id=sale.id,
            product_id=product.id,
            quantity=int(item['quantity']),
            price_each=float(item['unit_price']),
            total_price=float(item['quantity']) * float(item['unit_price'])
        )
        sale.line_items.append(line_item)

def get_or_create_product(shipstation_item):
    product = Product.query.filter_by(sku=shipstation_item['sku']).first()
    if not product:
        product = Product(
            sku=shipstation_item['sku'],
            description=shipstation_item['name'],
            price=float(shipstation_item['unit_price'])
        )
        db.session.add(product)
        db.session.flush()  # This assigns an ID to the new product
    return product

@click.command('create-admin')
@with_appcontext
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def create_admin(username, password):
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=4444)