# app.py
import click
from datetime import datetime
from decimal import Decimal
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask.cli import with_appcontext
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
import logging

app = Flask(__name__)

# Use environment variable for secret key, with a fallback for development
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sales.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
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
    sales = db.relationship('SalesReceipt', backref='customer', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)

class SalesReceipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    total = db.Column(db.Float, nullable=False)
    tax = db.Column(db.Float, nullable=False)
    shipping = db.Column(db.Float, nullable=False)
    line_items = db.relationship('LineItem', backref='sales_receipt', lazy=True)

class LineItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_id = db.Column(db.Integer, db.ForeignKey('sales_receipt.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_each = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    product = db.relationship('Product')

@app.template_filter('nl2br')
def nl2br(value):
    return value.replace('\n', '<br>\n')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        'date': sale.date.strftime('%Y-%m-%d %H:%M:%S'),
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
            for i, product_id in enumerate(request.form.getlist('product_id[]')):
                quantity = int(request.form.getlist('quantity[]')[i])
                price_each = Decimal(request.form.getlist('price_each[]')[i])
                total_price = quantity * price_each
                
                new_line_item = LineItem(
                    receipt_id=sale.id,  # Explicitly set the receipt_id
                    product_id=int(product_id),
                    quantity=quantity,
                    price_each=price_each,
                    total_price=total_price
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