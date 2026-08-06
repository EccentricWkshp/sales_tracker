"""Every page and JSON endpoint renders for a logged-in operator.

Cheap, but it is the check that catches a broken template or a Jinja reference
to a renamed column — neither shows up in unit tests of the functions below.
"""
import pytest


@pytest.mark.parametrize('path', [
    '/', '/sales', '/customers', '/products', '/management', '/state_taxes',
    '/finance', '/finance/banking', '/sales/pending',
])
def test_page_renders(client, path):
    assert client.get(path).status_code == 200


@pytest.mark.parametrize('path', [
    '/api/sales', '/api/customers', '/api/products', '/api/transactions',
    '/api/pending_orders', '/api/pending_orders/count',
    '/api/state_taxes_data?year=2026&quarter=Q2',
])
def test_api_endpoint_returns_json(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.is_json


def test_record_pages_render(client, customer_id, widget_id, make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 2, 100)], tax=8, shipping=5)
    for path in (f'/sales/view/{sale_id}', f'/sales/edit/{sale_id}',
                 f'/sales/print/{sale_id}', f'/sales/get/{sale_id}',
                 f'/customers/view/{customer_id}', f'/customers/get/{customer_id}',
                 f'/api/customer_orders/{customer_id}',
                 f'/api/product/{widget_id}',
                 f'/api/products/{widget_id}/attachments'):
        assert client.get(path).status_code == 200, path


def test_missing_records_404(client):
    for path in ('/sales/view/99999', '/sales/get/99999', '/customers/view/99999',
                 '/api/product/99999'):
        assert client.get(path).status_code == 404, path


def test_state_taxes_data_rejects_a_missing_quarter(client):
    assert client.get('/api/state_taxes_data?year=2026').status_code == 400
    assert client.get('/api/state_taxes_data?year=2026&quarter=Q9').status_code == 400


def test_dashboard_shows_the_pending_banner_only_when_something_waits(A, client):
    banner = b'waiting for customer details'
    assert banner not in client.get('/').data

    with A.app.app_context():
        A.db.session.add(A.PendingOrder(
            source='shopify', external_order_id='P-1', external_order_number='#P-1',
            payload='{}'))
        A.db.session.commit()

    body = client.get('/').data
    assert banner in body
    # Singular wording for one order, so the banner never reads "1 orders are"
    collapsed = ' '.join(body.decode().split())
    assert '1 imported order is waiting for customer details' in collapsed
