"""Etsy and eBay field mapping — pure translation, no database or network.

Neither has been verified against a live API (no developer credentials yet), so
these fixture payloads are the whole safety net under the mapping. They are
modelled on the documented response shapes.
"""
from datetime import date, datetime

import pytest


# --- Money helpers ----------------------------------------------------------

def test_etsy_money_applies_the_divisor(A):
    """Etsy sends {'amount': 1250, 'divisor': 100}, never 12.50."""
    assert A.etsy_money({'amount': 4567, 'divisor': 100}) == A.Decimal('45.67')
    assert A.etsy_money({'amount': 1250, 'divisor': 100}) == A.Decimal('12.50')


@pytest.mark.parametrize('value', [None, 'bad', {}, [], 0])
def test_etsy_money_survives_junk(A, value):
    assert A.etsy_money(value) == A.Decimal('0')


def test_etsy_money_treats_a_zero_divisor_as_the_default(A):
    """`value.get('divisor') or 100` catches 0 before the explicit zero guard
    below it, so a nonsense divisor falls back to Etsy's usual 100 rather than
    zeroing the amount. (That guard is therefore unreachable.)"""
    assert A.etsy_money({'amount': 5, 'divisor': 0}) == A.Decimal('0.05')


def test_ebay_money_reads_the_value_string(A):
    assert A.ebay_money({'value': '89.99', 'currency': 'USD'}) == A.Decimal('89.99')


@pytest.mark.parametrize('value', [None, 'bad', {}, {'value': 'not-a-number'}])
def test_ebay_money_survives_junk(A, value):
    assert A.ebay_money(value) == A.Decimal('0')


# --- State normalisation ----------------------------------------------------

def test_a_full_state_name_becomes_the_usps_code(A):
    """get_state_info, and so the WA B&O report, only recognises the code."""
    assert A.us_state_code('Washington') == 'WA'
    assert A.us_state_code('washington') == 'WA'
    assert A.us_state_code('WA') == 'WA'
    assert A.us_state_code('wa') == 'WA'


def test_an_unrecognised_region_passes_through_unchanged(A):
    """A non-US province must still reach the address line intact."""
    assert A.us_state_code('Ontario') == 'Ontario'
    assert A.us_state_code('') == ''
    assert A.us_state_code(None) == ''


# --- Etsy -------------------------------------------------------------------

ETSY_RECEIPT = {
    'receipt_id': 3312345678, 'status': 'Completed',
    'created_timestamp': int(datetime(2026, 7, 15, 10, 30).timestamp()),
    'name': 'Jane Buyer', 'buyer_email': 'jane@example.com',
    'first_line': '12 Main St', 'second_line': 'Apt 4', 'city': 'Centralia',
    'state': 'Washington', 'zip': '98531', 'country_iso': 'US',
    'grandtotal': {'amount': 4567, 'divisor': 100, 'currency_code': 'USD'},
    'total_tax_cost': {'amount': 350, 'divisor': 100},
    'total_shipping_cost': {'amount': 714, 'divisor': 100},
    'message_from_buyer': 'please gift wrap',
    'transactions': [{'title': 'Widget', 'sku': 'WID-1', 'quantity': 2,
                      'price': {'amount': 1750, 'divisor': 100}}],
    'shipments': [{'carrier_name': 'USPS Priority', 'tracking_code': '9200TRACK',
                   'shipment_notification_timestamp':
                       int(datetime(2026, 7, 16).timestamp())}],
}


@pytest.fixture
def etsy_order(A, ctx):
    return A.process_etsy_data([ETSY_RECEIPT])[0]


def test_etsy_maps_the_money(etsy_order):
    assert str(etsy_order['order_total']) == '45.67'
    assert str(etsy_order['tax_amount']) == '3.50'
    assert str(etsy_order['shipping_amount']) == '7.14'
    assert str(etsy_order['items'][0]['unit_price']) == '17.50'


def test_etsy_normalises_the_state(etsy_order):
    assert etsy_order['customer']['state'] == 'WA'


def test_etsy_maps_the_shipment(etsy_order):
    assert etsy_order['tracking'] == '9200TRACK'
    assert etsy_order['shipservice'] == 'USPS'      # first word, upper-cased
    assert etsy_order['shipdate'] == date(2026, 7, 16)


def test_etsy_identifiers(etsy_order):
    assert etsy_order['external_order_id'] == '3312345678'
    assert etsy_order['external_order_number'] == '3312345678'


def test_etsy_carries_the_buyer_and_the_note(etsy_order):
    assert etsy_order['customer']['name'] == 'Jane Buyer'
    assert etsy_order['customer']['email'] == 'jane@example.com'
    assert etsy_order['customer_notes'] == 'please gift wrap'
    assert etsy_order['customer_data_unavailable'] is False


def test_etsy_skips_a_cancelled_receipt(A, ctx):
    assert A.process_etsy_data([dict(ETSY_RECEIPT, status='Canceled')]) == []


def test_etsy_skips_a_malformed_receipt_without_losing_the_batch(A, ctx):
    """One bad receipt must not discard the whole fetch."""
    processed = A.process_etsy_data([{'no_receipt_id': True}, ETSY_RECEIPT])
    assert len(processed) == 1
    assert processed[0]['external_order_id'] == '3312345678'


def test_etsy_drops_a_zero_quantity_line(A, ctx):
    receipt = dict(ETSY_RECEIPT, transactions=[
        {'title': 'Nothing', 'sku': 'X', 'quantity': 0,
         'price': {'amount': 100, 'divisor': 100}}])
    assert A.process_etsy_data([receipt])[0]['items'] == []


def test_etsy_marks_a_withheld_buyer(A, ctx):
    anonymous = dict(ETSY_RECEIPT, name='', buyer_email='', first_line='', zip='')
    assert A.process_etsy_data([anonymous])[0]['customer_data_unavailable'] is True


def test_the_etsy_api_key_joins_both_credentials(A, ctx):
    """'keystring:shared_secret' — the keystring alone is refused."""
    credentials = A.EtsyCredentials(client_id='KEY', client_secret='SHH')
    A.db.session.add(credentials)
    A.db.session.commit()
    assert A.etsy_api_key(A.INTEGRATIONS['etsy'], credentials) == 'KEY:SHH'


def test_a_missing_shared_secret_is_reported_clearly(A, ctx):
    credentials = A.EtsyCredentials(client_id='KEY', client_secret='')
    A.db.session.add(credentials)
    A.db.session.commit()
    with pytest.raises(A.IntegrationError, match='shared secret'):
        A.etsy_api_key(A.INTEGRATIONS['etsy'], credentials)


# --- eBay -------------------------------------------------------------------

EBAY_ORDER = {
    'orderId': '12-34567-89012', 'legacyOrderId': '987654321',
    'creationDate': '2026-07-20T18:45:00.000Z',
    'orderPaymentStatus': 'PAID',
    'pricingSummary': {'total': {'value': '89.99', 'currency': 'USD'},
                       'tax': {'value': '7.20'},
                       'deliveryCost': {'value': '5.00'}},
    'fulfillmentStartInstructions': [{'shippingStep': {'shipTo': {
        'fullName': 'Sam Seller', 'email': 'sam@example.com',
        'primaryPhone': {'phoneNumber': '5551234'},
        'contactAddress': {'addressLine1': '9 Oak Ave', 'city': 'Olympia',
                           'stateOrProvince': 'WA', 'postalCode': '98501',
                           'countryCode': 'US'}}}}],
    'lineItems': [{'sku': 'EB-1', 'title': 'Gadget', 'quantity': 1,
                   'lineItemCost': {'value': '77.79'}}],
    'shippingFulfillments': [{'shipmentTrackingNumber': '1ZTRACK',
                              'shippingCarrierCode': 'UPS Ground',
                              'shippedDate': '2026-07-21T12:00:00.000Z'}],
}


@pytest.fixture
def ebay_order(A, ctx):
    return A.process_ebay_data([EBAY_ORDER])[0]


def test_ebay_maps_the_money(ebay_order):
    assert str(ebay_order['order_total']) == '89.99'
    assert str(ebay_order['tax_amount']) == '7.20'
    assert str(ebay_order['shipping_amount']) == '5.00'


def test_ebay_identifiers_are_not_interchangeable(ebay_order):
    """The human-facing number is the legacy id; the match key is orderId."""
    assert ebay_order['external_order_number'] == '987654321'
    assert ebay_order['external_order_id'] == '12-34567-89012'


def test_ebay_maps_the_shipment(ebay_order):
    assert ebay_order['tracking'] == '1ZTRACK'
    assert ebay_order['shipservice'] == 'UPS'
    assert ebay_order['shipdate'] == date(2026, 7, 21)


def test_ebay_dates_are_naive_local(ebay_order):
    """Every other write path stores naive local; a tz-aware value sorts wrong
    and can push a sale into the neighbouring quarter on the tax report."""
    assert ebay_order['order_date'].tzinfo is None


def test_ebay_carries_the_buyer(ebay_order):
    customer = ebay_order['customer']
    assert customer['name'] == 'Sam Seller'
    assert customer['email'] == 'sam@example.com'
    assert customer['phone'] == '5551234'
    assert customer['state'] == 'WA'
    assert ebay_order['customer_data_unavailable'] is False


def test_ebay_skips_an_unpaid_order(A, ctx):
    assert A.process_ebay_data([dict(EBAY_ORDER, orderPaymentStatus='FAILED')]) == []


def test_an_anonymised_ebay_buyer_goes_to_the_pending_queue(A, ctx):
    """eBay withholds contact details on most orders — expect this to be the
    common case, not the exception."""
    anonymous = dict(EBAY_ORDER, fulfillmentStartInstructions=[])
    processed = A.process_ebay_data([anonymous])[0]
    assert processed['customer_data_unavailable'] is True
    assert 'withheld' in processed['internal_notes']


def test_ebay_skips_a_malformed_order_without_losing_the_batch(A, ctx):
    processed = A.process_ebay_data([{'no_order_id': True}, EBAY_ORDER])
    assert len(processed) == 1


def test_ebay_falls_back_to_the_orderid_when_there_is_no_legacy_number(A, ctx):
    order = {k: v for k, v in EBAY_ORDER.items() if k != 'legacyOrderId'}
    assert A.process_ebay_data([order])[0]['external_order_number'] == '12-34567-89012'


def test_ebay_timestamps_convert_to_naive_local(A):
    parsed = A.parse_ebay_datetime('2026-07-20T18:45:00.000Z')
    assert parsed is not None and parsed.tzinfo is None
    assert A.parse_ebay_datetime(None) is None
    assert A.parse_ebay_datetime('not-a-date') is None


def test_ebay_hosts_switch_with_the_sandbox_flag(A, ctx):
    sandbox = A.EbayCredentials(sandbox=True)
    production = A.EbayCredentials(sandbox=False)
    assert A.ebay_host(sandbox, 'api') == 'https://api.sandbox.ebay.com'
    assert A.ebay_host(production, 'api') == 'https://api.ebay.com'


# --- Shared: timezone normalisation ----------------------------------------

def test_to_local_naive_strips_the_offset(A):
    aware = datetime(2026, 2, 1, 18, 30, tzinfo=A.timezone.utc)
    assert A.to_local_naive(aware).tzinfo is None
    # Already-naive values pass through untouched
    naive = datetime(2026, 2, 1, 10, 30)
    assert A.to_local_naive(naive) == naive
    assert A.to_local_naive(None) is None


# --- Both processors satisfy the pipeline's contract ------------------------

REQUIRED_KEYS = {
    'external_order_id', 'external_order_number', 'order_date', 'customer',
    'customer_data_unavailable', 'items', 'order_total', 'tax_amount',
    'shipping_amount', 'customer_notes', 'internal_notes', 'shipservice',
    'tracking', 'shipdate',
}


@pytest.mark.parametrize('processor,payload', [
    ('process_etsy_data', ETSY_RECEIPT),
    ('process_ebay_data', EBAY_ORDER),
])
def test_the_processed_shape_matches_what_the_importer_reads(A, ctx, processor,
                                                             payload):
    order = getattr(A, processor)([payload])[0]
    assert REQUIRED_KEYS <= set(order), REQUIRED_KEYS - set(order)
    for item in order['items']:
        assert {'sku', 'name', 'quantity', 'unit_price'} <= set(item)


@pytest.mark.parametrize('processor,payload,source', [
    ('process_etsy_data', ETSY_RECEIPT, 'etsy'),
    ('process_ebay_data', EBAY_ORDER, 'ebay'),
])
def test_a_processed_order_imports_end_to_end(A, ctx, processor, payload, source):
    """The mapping is only correct if the pipeline can actually store it."""
    processed = getattr(A, processor)([payload])
    result = A.import_processed_orders(processed, source)

    assert result.created == 1 and result.errors == []
    sale = A.SalesReceipt.query.filter_by(source=source).one()
    assert sale.receipt_number == str(sale.id)
    assert A.get_state_info(sale.customer.shipping_address).endswith('WA 98501') \
        or A.get_state_info(sale.customer.shipping_address).endswith('WA 98531')
