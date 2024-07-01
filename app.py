# app.py
import click
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask.cli import with_appcontext
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from sqlalchemy import func

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

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)

class SalesReceipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    total = db.Column(db.Float, nullable=False)
    tax = db.Column(db.Float, nullable=False)
    shipping = db.Column(db.Float, nullable=False)

class LineItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_id = db.Column(db.Integer, db.ForeignKey('sales_receipt.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_each = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

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
            return redirect(url_for('index'))
        flash('Invalid username or password')
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

@app.route('/customers/add', methods=['GET', 'POST'])
@login_required
def add_customer():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        billing_address = request.form['billing_address']
        shipping_address = request.form['shipping_address']
        
        new_customer = Customer(name=name, email=email, billing_address=billing_address, shipping_address=shipping_address)
        db.session.add(new_customer)
        db.session.commit()
        flash('Customer added successfully')
        return redirect(url_for('customers'))
    return render_template('add_customer.html')

@app.route('/customers/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_customer(id):
    customer = Customer.query.get_or_404(id)
    if request.method == 'POST':
        customer.name = request.form['name']
        customer.email = request.form['email']
        customer.billing_address = request.form['billing_address']
        customer.shipping_address = request.form['shipping_address']
        db.session.commit()
        flash('Customer updated successfully')
        return redirect(url_for('customers'))
    return render_template('edit_customer.html', customer=customer)

@app.route('/customers/delete/<int:id>')
@login_required
def delete_customer(id):
    customer = Customer.query.get_or_404(id)
    db.session.delete(customer)
    db.session.commit()
    flash('Customer deleted successfully')
    return redirect(url_for('customers'))

@app.route('/products')
@login_required
def products():
    products = Product.query.all()
    return render_template('products.html', products=products)

@app.route('/products/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        sku = request.form['sku']
        description = request.form['description']
        price = float(request.form['price'])
        
        new_product = Product(sku=sku, description=description, price=price)
        db.session.add(new_product)
        db.session.commit()
        flash('Product added successfully', 'success')
        return redirect(url_for('products'))
    return render_template('add_product.html')

@app.route('/products/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_product(id):
    product = Product.query.get_or_404(id)
    if request.method == 'POST':
        product.sku = request.form['sku']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        db.session.commit()
        flash('Product updated successfully', 'success')
        return redirect(url_for('products'))
    return render_template('edit_product.html', product=product)

@app.route('/products/delete/<int:id>')
@login_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully', 'success')
    return redirect(url_for('products'))

@app.route('/sales')
@login_required
def sales():
    receipts = SalesReceipt.query.all()
    return render_template('sales.html', receipts=receipts)

@app.route('/sales/add', methods=['GET', 'POST'])
@login_required
def add_sale():
    if request.method == 'POST':
        customer_id = request.form['customer_id']
        total = float(request.form['total'])
        tax = float(request.form['tax'])
        shipping = float(request.form['shipping'])
        
        new_receipt = SalesReceipt(customer_id=customer_id, total=total, tax=tax, shipping=shipping)
        db.session.add(new_receipt)
        db.session.commit()
        
        # Add line items
        line_items = json.loads(request.form['line_items'])
        for item in line_items:
            new_line_item = LineItem(
                receipt_id=new_receipt.id,
                product_id=item['product_id'],
                quantity=item['quantity'],
                price_each=item['price_each'],
                total_price=item['total_price']
            )
            db.session.add(new_line_item)
        
        db.session.commit()
        flash('Sales receipt added successfully', 'success')
        return redirect(url_for('sales'))
    
    customers = Customer.query.all()
    products = Product.query.all()
    return render_template('add_sale.html', customers=customers, products=products)

@app.route('/sales/view/<int:id>')
@login_required
def view_sale(id):
    receipt = SalesReceipt.query.get_or_404(id)
    line_items = LineItem.query.filter_by(receipt_id=id).all()
    return render_template('view_sale.html', receipt=receipt, line_items=line_items)

@app.route('/sales/delete/<int:id>')
@login_required
def delete_sale(id):
    receipt = SalesReceipt.query.get_or_404(id)
    LineItem.query.filter_by(receipt_id=id).delete()
    db.session.delete(receipt)
    db.session.commit()
    flash('Sales receipt deleted successfully', 'success')
    return redirect(url_for('sales'))

@app.route('/api/calculate_tax', methods=['POST'])
@login_required
def calculate_tax():
    total = float(request.json['total'])
    # Assuming a flat 1.5% B&O tax rate for this example
    tax = total * 0.015
    return jsonify({'tax': round(tax, 2)})

@app.route('/api/get_product/<int:id>')
@login_required
def get_product(id):
    product = Product.query.get_or_404(id)
    return jsonify({
        'id': product.id,
        'sku': product.sku,
        'description': product.description,
        'price': product.price
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=4444)