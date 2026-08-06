"""Shopify: webhook security, both auth routes, token caching, field mapping.

Nothing here reaches the network. The token exchange is intercepted by replacing
``integration_request``; the webhook is exercised through the real route with a
signature computed the way Shopify computes it.
"""
import base64
import hashlib
import hmac
import json
from decimal import Decimal

import pytest

SHOP = 'test-shop.myshopify.com'
API_SECRET = 'api-secret-value'
CLIENT_SECRET = 'client-secret-value'


@pytest.fixture
def shopify_credentials(A):
    """A configured store with webhooks on, on the legacy token route."""
    def _configure(**overrides):
        with A.app.app_context():
            credentials = A.ShopifyCredentials.query.first()
            if credentials is None:
                credentials = A.ShopifyCredentials(api_key='')
                A.db.session.add(credentials)
            credentials.shop_domain = SHOP
            credentials.auth_mode = 'token'
            credentials.api_key = 'shpat_test'
            credentials.api_secret = API_SECRET
            credentials.client_id = ''
            credentials.client_secret = ''
            credentials.access_token = ''
            credentials.access_token_expires_at = None
            credentials.enabled = True
            credentials.webhooks_enabled = True
            for field, value in overrides.items():
                setattr(credentials, field, value)
            A.db.session.commit()
            return credentials.id
    return _configure


def order_payload(**overrides):
    payload = {
        'id': 998877,
        'name': '#TEST-1',
        'order_number': 'TEST-1',
        'created_at': '2026-02-01T10:30:00-08:00',
        'email': 'shopify-buyer@example.com',
        'total_price': '110.00',
        'total_tax': '8.00',
        'total_shipping_price_set': {'shop_money': {'amount': '2.00'}},
        'note': 'webhook test',
        'shipping_address': {
            'name': 'Shopify Buyer', 'address1': '123 Test St', 'city': 'Olympia',
            'province_code': 'WA', 'zip': '98501', 'country_code': 'US'},
        'line_items': [{'sku': 'ZZ-SHOP', 'title': 'Shop Widget',
                        'quantity': 2, 'price': '50.00'}],
        'fulfillments': [{'tracking_number': '9400111', 'tracking_company': 'USPS',
                          'created_at': '2026-02-02T09:00:00-08:00'}],
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


def sign(body, secret=API_SECRET):
    return base64.b64encode(
        hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()


def deliver(client, body, signature=None, shop=SHOP, topic='orders/create'):
    headers = {'X-Shopify-Topic': topic, 'Content-Type': 'application/json'}
    if signature is not None:
        headers['X-Shopify-Hmac-Sha256'] = signature
    if shop is not None:
        headers['X-Shopify-Shop-Domain'] = shop
    return client.post('/shopify/webhook', data=body, headers=headers)


# --- Webhook security -------------------------------------------------------

def test_webhook_404s_while_disabled(anon_client):
    """The endpoint must not exist for anyone scanning the host."""
    assert deliver(anon_client, b'{}', 'anything').status_code == 404


def test_webhook_404s_when_only_the_integration_is_on(A, anon_client,
                                                      shopify_credentials):
    shopify_credentials(webhooks_enabled=False)
    assert deliver(anon_client, b'{}', 'anything').status_code == 404


def test_webhook_rejects_a_bad_signature(anon_client, shopify_credentials):
    shopify_credentials()
    assert deliver(anon_client, order_payload(), 'wrong').status_code == 401


def test_webhook_rejects_a_missing_signature(anon_client, shopify_credentials):
    shopify_credentials()
    assert deliver(anon_client, order_payload(), None).status_code == 401


def test_webhook_rejects_a_foreign_shop_domain(anon_client, shopify_credentials):
    shopify_credentials()
    body = order_payload()
    response = deliver(anon_client, body, sign(body),
                       shop='someone-else.myshopify.com')
    assert response.status_code == 401


def test_a_tampered_body_fails_the_signature(anon_client, shopify_credentials):
    """The signature covers the exact bytes, so re-serialising invalidates it."""
    shopify_credentials()
    body = order_payload()
    signature = sign(body)
    tampered = body.replace(b'"110.00"', b'"1.00"')
    assert deliver(anon_client, tampered, signature).status_code == 401


def test_webhook_accepts_a_valid_signature(A, anon_client, shopify_credentials):
    shopify_credentials()
    body = order_payload()
    response = deliver(anon_client, body, sign(body))

    assert response.status_code == 200, response.data
    assert response.get_json()['created'] == 1
    with A.app.app_context():
        assert A.SalesReceipt.query.filter_by(source='shopify',
                                              external_order_id='998877').count() == 1


def test_an_unparseable_body_is_a_400(anon_client, shopify_credentials):
    shopify_credentials()
    body = b'{not json'
    assert deliver(anon_client, body, sign(body)).status_code == 400


def test_replaying_a_delivery_updates_and_never_duplicates(A, anon_client,
                                                           shopify_credentials):
    """Deliveries are at-least-once."""
    shopify_credentials()
    body = order_payload()
    signature = sign(body)

    deliver(anon_client, body, signature)
    response = deliver(anon_client, body, signature, topic='orders/updated')

    assert response.get_json() == {'status': 'ok', 'created': 0, 'updated': 1,
                                   'adopted': 0, 'pending': 0}
    with A.app.app_context():
        assert A.SalesReceipt.query.count() == 1


def test_the_client_credentials_route_signs_with_the_client_secret(
        A, anon_client, shopify_credentials):
    shopify_credentials(auth_mode='client_credentials', client_id='client-abc',
                        client_secret=CLIENT_SECRET)
    body = order_payload()

    assert deliver(anon_client, body, sign(body, API_SECRET)).status_code == 401
    assert deliver(anon_client, body, sign(body, CLIENT_SECRET)).status_code == 200


# --- The imported sale ------------------------------------------------------

def test_the_imported_sale_is_correct(A, anon_client, shopify_credentials):
    shopify_credentials()
    body = order_payload()
    deliver(anon_client, body, sign(body))

    with A.app.app_context():
        sale = A.SalesReceipt.query.filter_by(external_order_id='998877').one()
        assert sale.total == Decimal('110.00')
        assert sale.tax == Decimal('8.00')
        assert sale.shipping == Decimal('2.00')
        assert sale.tracking == '9400111'
        assert sale.shipservice == 'USPS'
        assert str(sale.shipdate) == '2026-02-02'
        # Stored naive local, like every other write path
        assert sale.date.tzinfo is None
        assert sale.receipt_number == str(sale.id)
        assert sale.external_order_number == '#TEST-1'

        item = sale.line_items[0]
        assert item.quantity == 2 and item.price_each == Decimal('50.00')
        assert A.get_state_info(sale.customer.shipping_address) == 'Olympia, WA 98501'


def test_a_withheld_buyer_goes_to_the_pending_queue(A, anon_client,
                                                    shopify_credentials):
    """Below the Advanced plan Shopify returns null for the identifying fields
    but still sends province_code and country_code."""
    shopify_credentials()
    body = order_payload(id=555001, name='#PII-1', email=None, customer=None,
                         shipping_address={'name': None, 'address1': None,
                                           'city': None, 'zip': None,
                                           'province_code': 'WA',
                                           'country_code': 'US'})
    response = deliver(anon_client, body, sign(body))

    assert response.status_code == 200
    assert response.get_json()['pending'] == 1
    assert response.get_json()['created'] == 0
    with A.app.app_context():
        assert A.SalesReceipt.query.filter_by(external_order_id='555001').first() is None
        parked = A.PendingOrder.query.filter_by(external_order_id='555001').one()
        assert parked.location_hint() == 'WA, US'


def test_a_cancelled_order_is_acknowledged_and_ignored(A, anon_client,
                                                       shopify_credentials):
    """Acknowledge so Shopify stops retrying."""
    shopify_credentials()
    body = order_payload(cancelled_at='2026-02-03T10:00:00-08:00')
    response = deliver(anon_client, body, sign(body))

    assert response.status_code == 200
    with A.app.app_context():
        assert A.SalesReceipt.query.count() == 0


# --- Auth routes and token caching -----------------------------------------

def test_the_token_route_uses_the_stored_admin_token(A, ctx,
                                                     shopify_credentials):
    shopify_credentials()
    credentials = A.ShopifyCredentials.query.one()
    assert A.shopify_access_token(credentials) == 'shpat_test'
    assert A.shopify_webhook_secret(credentials) == API_SECRET


def test_the_client_credentials_route_exchanges_for_a_token(A, ctx, monkeypatch,
                                                            shopify_credentials):
    shopify_credentials(auth_mode='client_credentials', client_id='client-abc',
                        client_secret=CLIENT_SECRET, api_key='')
    calls = []

    class FakeResponse:
        status_code, headers = 200, {}

        def json(self):
            return {'access_token': 'shpat_from_exchange',
                    'scope': 'read_orders,read_products', 'expires_in': 86399}

    def fake_request(method, url, label, **kwargs):
        calls.append((method, url, kwargs.get('data')))
        return FakeResponse()

    monkeypatch.setattr(A, 'integration_request', fake_request)
    credentials = A.ShopifyCredentials.query.one()

    assert A.shopify_access_token(credentials) == 'shpat_from_exchange'
    assert calls[0][1].endswith('/admin/oauth/access_token')
    assert calls[0][2]['grant_type'] == 'client_credentials'
    assert credentials.access_token_expires_at is not None

    # Cached, so a second call must not hit the network again
    assert A.shopify_access_token(credentials) == 'shpat_from_exchange'
    assert len(calls) == 1

    # A token about to lapse is renewed early rather than expiring mid-import
    credentials.access_token_expires_at = A.datetime.now() + A.timedelta(minutes=1)
    A.db.session.commit()
    A.shopify_access_token(credentials)
    assert len(calls) == 2


def test_a_token_with_no_order_scope_is_refused(A, ctx, monkeypatch,
                                                shopify_credentials):
    """Shopify issues one even when no scopes were approved, and every orders
    request then 403s with nothing to explain it."""
    shopify_credentials(auth_mode='client_credentials', client_id='client-abc',
                        client_secret=CLIENT_SECRET, api_key='')

    class FakeResponse:
        status_code, headers = 200, {}

        def json(self):
            return {'access_token': 'shpat_x', 'scope': '', 'expires_in': 86399}

    monkeypatch.setattr(A, 'integration_request',
                        lambda *a, **k: FakeResponse())
    credentials = A.ShopifyCredentials.query.one()

    with pytest.raises(A.IntegrationError, match='read_orders'):
        A.shopify_access_token(credentials)
    # Nothing cached: a scopeless token is not worth reusing for 24 hours
    assert not credentials.access_token


def test_the_auth_mode_is_inferred_when_unset(A, ctx, shopify_credentials):
    shopify_credentials(auth_mode='', client_id='client-abc',
                        client_secret=CLIENT_SECRET)
    credentials = A.ShopifyCredentials.query.one()
    assert A.shopify_auth_mode(credentials) == 'client_credentials'


# --- Environment overrides --------------------------------------------------

def test_an_environment_value_beats_the_stored_one(A, ctx, monkeypatch,
                                                   shopify_credentials):
    shopify_credentials(client_id='stored-client-id')
    credentials = A.ShopifyCredentials.query.one()

    monkeypatch.setenv('SHOPIFY_CLIENT_ID', 'env-client-id')
    assert A.shopify_setting(credentials, 'client_id') == 'env-client-id'
    monkeypatch.delenv('SHOPIFY_CLIENT_ID')
    assert A.shopify_setting(credentials, 'client_id') == 'stored-client-id'


def test_a_pasted_url_normalises_to_a_bare_host(A, ctx, monkeypatch,
                                                shopify_credentials):
    shopify_credentials()
    credentials = A.ShopifyCredentials.query.one()
    monkeypatch.setenv('SHOPIFY_SHOP_DOMAIN', 'https://env-store.myshopify.com/')
    assert A.shopify_shop_domain(credentials) == 'env-store.myshopify.com'


# --- Paging -----------------------------------------------------------------

def test_the_next_page_url_is_read_from_the_link_header(A):
    header = ('<https://x.myshopify.com/admin/api/2026-01/orders.json?page_info=abc>; '
              'rel="next"')
    assert A.shopify_next_page_url(header).endswith('page_info=abc')


def test_a_link_header_with_only_previous_ends_paging(A):
    header = '<https://x.myshopify.com/orders.json?page_info=zzz>; rel="previous"'
    assert A.shopify_next_page_url(header) is None
    assert A.shopify_next_page_url('') is None
    assert A.shopify_next_page_url(None) is None


# --- Route gating -----------------------------------------------------------

def test_the_fetch_route_refuses_while_disabled(client):
    """No outbound call may be attempted before the operator switches it on."""
    response = client.post('/shopify/fetch_orders',
                           data={'start_date': '2026-01-01', 'end_date': '2026-01-02'})
    assert response.status_code == 400
