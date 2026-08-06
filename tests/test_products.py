"""Product fields, validation and margin (roadmap F2)."""
from decimal import Decimal

import pytest


def test_add_stores_every_new_field(A, client):
    response = client.post('/products/add', json={
        'sku': 'F2-1', 'description': 'Test widget', 'price': '$1,299.99',
        'cost': '$400.50', 'weight_oz': '12.5', 'category': 'Widgets',
        'vendor': 'Acme Supply', 'notes': 'Two-part build.',
        'is_manufactured': True})
    assert response.status_code == 200, response.data
    product_id = response.get_json()['id']

    with A.app.app_context():
        product = A.db.session.get(A.Product, product_id)
        assert float(product.price) == 1299.99      # '$1,299.99' parsed
        assert float(product.cost) == 400.50
        assert float(product.weight_oz) == 12.5
        assert product.category == 'Widgets'
        assert product.vendor == 'Acme Supply'
        assert product.notes == 'Two-part build.'
        assert product.is_manufactured is True


def test_margin_is_derived_not_stored(A, client):
    product_id = client.post('/products/add', json={
        'sku': 'F2-2', 'description': 'Margin check', 'price': '1299.99',
        'cost': '400.50'}).get_json()['id']
    with A.app.app_context():
        product = A.db.session.get(A.Product, product_id)
        assert product.margin == Decimal('899.49')
        assert 'margin' not in [c.name for c in A.Product.__table__.columns]


def test_margin_is_none_without_a_cost(A, client):
    product_id = client.post('/products/add', json={
        'sku': 'F2-3', 'description': 'No cost', 'price': '5.00',
        'cost': '', 'weight_oz': ''}).get_json()['id']
    with A.app.app_context():
        product = A.db.session.get(A.Product, product_id)
        assert product.margin is None
        assert product.to_dict()['margin'] is None


def test_to_dict_carries_the_new_fields(A, client):
    product_id = client.post('/products/add', json={
        'sku': 'F2-4', 'description': 'Dict check', 'price': '100',
        'cost': '40', 'weight_oz': '3', 'category': 'C', 'vendor': 'V'}
    ).get_json()['id']
    with A.app.app_context():
        payload = A.db.session.get(A.Product, product_id).to_dict()
    assert payload['cost'] == 40.0
    assert payload['margin'] == 60.0
    assert payload['weight_oz'] == 3.0
    assert payload['attachment_count'] == 0


PRODUCT_VALIDATION = [
    ('missing sku', {'description': 'x', 'price': '1'}, 400),
    ('missing description', {'sku': 'V1', 'price': '1'}, 400),
    ('missing price', {'sku': 'V2', 'description': 'x'}, 400),
    ('bad price', {'sku': 'V3', 'description': 'x', 'price': 'abc'}, 400),
    ('negative price', {'sku': 'V4', 'description': 'x', 'price': '-1'}, 400),
    ('bad cost', {'sku': 'V5', 'description': 'x', 'price': '1', 'cost': 'xyz'}, 400),
    ('negative cost', {'sku': 'V6', 'description': 'x', 'price': '1', 'cost': '-5'}, 400),
    ('bad weight', {'sku': 'V7', 'description': 'x', 'price': '1',
                    'weight_oz': 'heavy'}, 400),
    ('sku too long', {'sku': 'X' * 21, 'description': 'x', 'price': '1'}, 400),
    ('duplicate sku', {'sku': 'WIDGET-1', 'description': 'dupe', 'price': '1'}, 409),
]


@pytest.mark.parametrize('label,payload,expected', PRODUCT_VALIDATION,
                         ids=[row[0] for row in PRODUCT_VALIDATION])
def test_add_validation(client, label, payload, expected):
    response = client.post('/products/add', json=payload)
    assert response.status_code == expected, f'{label}: {response.data[:160]}'
    assert response.is_json


def test_blank_optional_numbers_are_accepted(client):
    response = client.post('/products/add', json={
        'sku': 'F2-5', 'description': 'Sparse', 'price': '5.00',
        'cost': '', 'weight_oz': '', 'category': '', 'vendor': '', 'notes': ''})
    assert response.status_code == 200, response.data


def test_edit_updates_the_new_fields(A, client, widget_id):
    response = client.post(f'/products/edit/{widget_id}', json={
        'sku': 'WIDGET-1', 'description': 'Standard widget v2', 'price': '130',
        'cost': '41', 'weight_oz': '13', 'category': 'Gadgets', 'vendor': 'Acme',
        'notes': 'Updated.', 'is_manufactured': False, 'archived': True})
    assert response.status_code == 200, response.data

    with A.app.app_context():
        product = A.db.session.get(A.Product, widget_id)
        assert product.category == 'Gadgets'
        assert float(product.cost) == 41
        assert product.archived is True
        assert product.is_manufactured is False


def test_edit_to_an_existing_sku_is_a_409(client, widget_id):
    response = client.post(f'/products/edit/{widget_id}', json={
        'sku': 'GADGET-1', 'description': 'Clash', 'price': '1'})
    assert response.status_code == 409


def test_archived_products_are_hidden_from_new_sales(A, client, customer_id):
    """They stay sellable on receipts that already reference them, but must not
    appear in the add-sale product list."""
    with A.app.app_context():
        archived_id = A.Product.query.filter_by(sku='OLD-1').one().id
    body = client.get('/sales').get_data(as_text=True)
    assert 'OLD-1' not in body

    # ...but an edit page for a sale using it must still render it
    with A.app.app_context():
        sale = A.SalesReceipt(customer_id=customer_id, date=A.datetime(2026, 5, 1),
                              total=5, tax=0, shipping=0, source='manual')
        A.db.session.add(sale)
        A.db.session.flush()
        A.db.session.add(A.LineItem(receipt_id=sale.id, product_id=archived_id,
                                    quantity=1, price_each=5, total_price=5))
        A.db.session.commit()
        sale_id = sale.id

    assert 'OLD-1' in client.get(f'/sales/edit/{sale_id}').get_data(as_text=True)


def test_archiving_a_product(A, client, widget_id):
    assert client.post(f'/products/archive/{widget_id}').status_code == 200
    with A.app.app_context():
        assert A.db.session.get(A.Product, widget_id).archived is True


def test_a_product_with_sales_cannot_be_deleted(A, client, customer_id,
                                                widget_id, make_sale):
    make_sale(customer_id, [(widget_id, 1, 100)])
    response = client.post(f'/products/delete/{widget_id}')
    assert response.status_code != 200 or not response.get_json().get('success')
    with A.app.app_context():
        assert A.db.session.get(A.Product, widget_id) is not None


def test_api_products_lists_the_grid_columns(client):
    rows = client.get('/api/products').get_json()
    assert rows
    for field in ('sku', 'price', 'cost', 'margin', 'weight_oz', 'category',
                  'vendor', 'attachment_count', 'archived'):
        assert field in rows[0], field
