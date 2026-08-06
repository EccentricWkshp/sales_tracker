"""``import_processed_orders`` — the shared spine of every importer.

Platform-specific field mapping is tested in ``test_marketplaces.py`` and
``test_shopify.py``; everything here works on the internal processed-order shape
(the ``processed_order`` fixture), because these behaviours must hold no matter
which platform produced the order.

Covers roadmap C1 (single session), C2 (per-order isolation), C4 (line items are
not rebuilt on re-import), the adoption of hand-entered receipts, and the
pending-order queue.
"""
from decimal import Decimal

import pytest


def _run(A, orders, source='shopify', enrich=None):
    return A.import_processed_orders(orders, source, enrich=enrich)


# --- Creating ---------------------------------------------------------------

def test_a_new_order_becomes_a_receipt(A, ctx, processed_order):
    result = _run(A, [processed_order()])
    assert (result.created, result.updated, result.adopted) == (1, 0, 0)
    assert result.errors == []

    sale = A.SalesReceipt.query.filter_by(source='shopify',
                                          external_order_id='EXT-1').one()
    assert sale.total == Decimal('108.00')
    assert sale.tax == Decimal('8.00')
    assert len(sale.line_items) == 1


def test_receipt_number_is_the_receipt_id_not_the_order_number(A, ctx,
                                                               processed_order):
    """The importers used to write the marketplace number into it."""
    _run(A, [processed_order(external_order_number='1797')])
    sale = A.SalesReceipt.query.filter_by(external_order_id='EXT-1').one()
    assert sale.receipt_number == str(sale.id)
    assert sale.external_order_number == '1797'
    assert sale.external_order_id == 'EXT-1'


def test_the_importer_creates_the_customer(A, ctx, processed_order):
    _run(A, [processed_order()])
    customer = A.Customer.query.filter_by(email='imported@example.com').one()
    assert customer.name == 'Imported Buyer'
    # The address must be classifiable by the state-taxes report
    assert A.get_state_info(customer.shipping_address) == 'Olympia, WA 98501'


def test_an_unknown_sku_creates_the_product(A, ctx, processed_order):
    _run(A, [processed_order(items=[{'sku': 'NEW-SKU', 'name': 'Novel thing',
                                     'quantity': 2,
                                     'unit_price': A.Decimal('12.50')}])])
    product = A.Product.query.filter_by(sku='NEW-SKU').one()
    assert product.description == 'Novel thing'

    item = A.SalesReceipt.query.one().line_items[0]
    assert item.quantity == 2
    assert item.total_price == Decimal('25.00')


def test_a_known_sku_is_reused(A, ctx, processed_order, widget_id):
    _run(A, [processed_order()])
    assert A.Product.query.filter_by(sku='WIDGET-1').count() == 1
    assert A.SalesReceipt.query.one().line_items[0].product_id == widget_id


# --- Re-import (C4) ---------------------------------------------------------

def test_reimport_updates_the_header_without_duplicating(A, ctx, processed_order):
    _run(A, [processed_order()])
    result = _run(A, [processed_order(order_total=A.Decimal('120.00'))])

    assert (result.created, result.updated) == (0, 1)
    assert A.SalesReceipt.query.count() == 1
    assert A.SalesReceipt.query.one().total == Decimal('120.00')


def test_reimport_preserves_hand_edited_line_items(A, ctx, processed_order):
    """The previous code deleted and rebuilt them on every fetch."""
    _run(A, [processed_order()])
    item = A.SalesReceipt.query.one().line_items[0]
    item.quantity, item.price_each, item.total_price = 7, 11.11, 77.77
    A.db.session.commit()

    _run(A, [processed_order()])

    item = A.SalesReceipt.query.one().line_items[0]
    assert item.quantity == 7
    assert item.price_each == Decimal('11.11')


def test_reimport_never_reassigns_the_customer(A, ctx, processed_order,
                                               make_customer):
    """Otherwise a manual customer merge is undone by the next fetch."""
    _run(A, [processed_order()])
    merged_into = make_customer('Merged Target', 'merged@example.com')
    sale = A.SalesReceipt.query.one()
    sale.customer_id = merged_into
    A.db.session.commit()

    _run(A, [processed_order()])
    assert A.SalesReceipt.query.one().customer_id == merged_into


def test_reimport_appends_notes_rather_than_replacing_them(A, ctx,
                                                           processed_order):
    _run(A, [processed_order(customer_notes='from the store')])
    sale = A.SalesReceipt.query.one()
    sale.internal_notes = 'checked by hand'
    A.db.session.commit()

    _run(A, [processed_order(customer_notes='from the store',
                             internal_notes='second pass')])

    sale = A.SalesReceipt.query.one()
    assert 'checked by hand' in sale.internal_notes
    assert 'second pass' in sale.internal_notes
    # Unchanged incoming text must not stack up on every run
    assert sale.customer_notes == 'from the store'


def test_matching_is_scoped_to_the_source(A, ctx, processed_order):
    """Two platforms using the same internal id are different orders."""
    _run(A, [processed_order(external_order_id='999')], source='shopify')
    _run(A, [processed_order(external_order_id='999',
                             customer={'name': 'Other Buyer',
                                       'email': 'other@example.com',
                                       'city': 'Tacoma', 'state': 'WA',
                                       'postal_code': '98402', 'country': 'US'})],
         source='etsy')
    assert A.SalesReceipt.query.count() == 2


# --- C2: one bad order must not discard the batch ---------------------------

def test_a_failing_order_is_isolated(A, ctx, processed_order):
    good = processed_order(external_order_id='GOOD-1', external_order_number='1')
    bad = processed_order(external_order_id='BAD-1', external_order_number='2',
                          order_total=None)   # NOT NULL violation
    good2 = processed_order(external_order_id='GOOD-2', external_order_number='3')

    result = _run(A, [good, bad, good2])

    assert result.created == 2
    assert len(result.errors) == 1
    assert 'Order 2' in result.errors[0]
    assert A.SalesReceipt.query.filter_by(external_order_id='BAD-1').first() is None
    assert A.SalesReceipt.query.filter_by(external_order_id='GOOD-2').first() is not None


def test_the_customer_created_during_an_import_is_committed(A, ctx,
                                                            processed_order):
    """C1: sales used to commit on a raw Session while the customer they pointed
    at was written to db.session and rolled back."""
    _run(A, [processed_order()])
    A.db.session.expunge_all()
    assert A.Customer.query.filter_by(email='imported@example.com').first() is not None


def test_an_enrich_failure_only_loses_that_order(A, ctx, processed_order):
    def enrich(order):
        if order['external_order_id'] == 'BOOM':
            raise RuntimeError('shipment lookup failed')

    result = _run(A, [processed_order(external_order_id='OK-1'),
                      processed_order(external_order_id='BOOM')], enrich=enrich)
    assert result.created == 1
    assert len(result.errors) == 1


def test_an_empty_batch_is_harmless(A, ctx):
    result = _run(A, [])
    assert result == (0, 0, 0, [], 0)


# --- Adoption of hand-entered receipts --------------------------------------

def test_an_order_entered_by_hand_is_adopted_not_duplicated(A, ctx,
                                                            processed_order,
                                                            customer_id,
                                                            widget_id, make_sale):
    """An operator who types the order themselves leaves external_order_id empty,
    so the reliable key cannot see it."""
    sale_id = make_sale(customer_id, [(widget_id, 1, 95)],
                        date=A.datetime(2026, 6, 1, 9, 0),
                        external_order_number='1797', source='manual')

    result = _run(A, [processed_order(external_order_id='EXT-9',
                                      external_order_number='1797')])

    assert (result.created, result.adopted) == (0, 1)
    assert A.SalesReceipt.query.count() == 1
    sale = A.db.session.get(A.SalesReceipt, sale_id)
    assert sale.external_order_id == 'EXT-9'


def test_an_adopted_receipt_keeps_the_operators_figures(A, ctx, processed_order,
                                                        customer_id, widget_id,
                                                        make_sale):
    """They may already account for a discount the API still reports at face
    value; overwriting them is the silent cleanup this matching avoids."""
    sale_id = make_sale(customer_id, [(widget_id, 1, 95)],
                        date=A.datetime(2026, 6, 1, 9, 0),
                        external_order_number='1797', source='manual')

    _run(A, [processed_order(external_order_id='EXT-9',
                             external_order_number='1797',
                             order_total=A.Decimal('999.00'))])

    sale = A.db.session.get(A.SalesReceipt, sale_id)
    assert sale.total == Decimal('95.00')
    assert sale.source == 'manual'
    assert 'Matched to shopify order 1797' in sale.internal_notes


def test_an_adopted_receipt_stays_adopted_on_the_next_run(A, ctx,
                                                          processed_order,
                                                          customer_id, widget_id,
                                                          make_sale):
    """Stamping it 'shopify' would make the next import treat it as its own and
    overwrite the operator's figures."""
    make_sale(customer_id, [(widget_id, 1, 95)],
              date=A.datetime(2026, 6, 1, 9, 0),
              external_order_number='1797', source='manual')
    order = processed_order(external_order_id='EXT-9',
                            external_order_number='1797',
                            order_total=A.Decimal('999.00'))

    _run(A, [order])
    _run(A, [order])

    sale = A.SalesReceipt.query.one()
    assert sale.source == 'manual'
    assert sale.total == Decimal('95.00')


def test_a_matching_number_on_a_different_day_is_not_adopted(A, ctx,
                                                             processed_order,
                                                             customer_id,
                                                             widget_id,
                                                             make_sale):
    """The order number alone is not unique; requiring the dates to agree makes a
    collision implausible."""
    make_sale(customer_id, [(widget_id, 1, 95)],
              date=A.datetime(2026, 1, 1, 9, 0),
              external_order_number='1797', source='manual')

    result = _run(A, [processed_order(external_order_id='EXT-9',
                                      external_order_number='1797')])
    assert (result.created, result.adopted) == (1, 0)
    assert A.SalesReceipt.query.count() == 2


def test_a_receipt_already_owned_by_an_importer_is_not_adopted(A, ctx,
                                                               processed_order,
                                                               customer_id,
                                                               widget_id,
                                                               make_sale):
    make_sale(customer_id, [(widget_id, 1, 95)],
              date=A.datetime(2026, 6, 1, 9, 0),
              external_order_number='1797', source='shipstation',
              external_order_id='SS-1')

    result = _run(A, [processed_order(external_order_id='EXT-9',
                                      external_order_number='1797')])
    assert result.created == 1


@pytest.mark.parametrize('typed,incoming', [
    ('#1797', '1797'),
    ('1797', '#1797'),
    (' 1797 ', '1797'),
])
def test_order_numbers_are_compared_the_way_a_person_would(A, ctx,
                                                           processed_order,
                                                           customer_id,
                                                           widget_id, make_sale,
                                                           typed, incoming):
    make_sale(customer_id, [(widget_id, 1, 95)],
              date=A.datetime(2026, 6, 1, 9, 0),
              external_order_number=typed, source='manual')
    result = _run(A, [processed_order(external_order_id='EXT-9',
                                      external_order_number=incoming)])
    assert result.adopted == 1


def test_legacy_rows_match_on_the_receipt_number(A, ctx, processed_order,
                                                 customer_id, widget_id,
                                                 make_sale):
    """Rows imported before `source` existed stored the marketplace number in
    what is now receipt_number."""
    sale_id = make_sale(customer_id, [(widget_id, 1, 95)], source=None)
    sale = A.db.session.get(A.SalesReceipt, sale_id)
    sale.receipt_number = '1797'
    A.db.session.commit()

    result = _run(A, [processed_order(external_order_id='EXT-9',
                                      external_order_number='1797')])
    assert (result.created, result.updated) == (0, 1)
    assert A.SalesReceipt.query.count() == 1


# --- The pending queue ------------------------------------------------------

def test_an_order_without_buyer_details_is_parked(A, ctx, processed_order):
    result = _run(A, [processed_order(customer_data_unavailable=True,
                                      customer={'name': None, 'email': None,
                                                'city': None, 'state': 'WA',
                                                'postal_code': None,
                                                'country': 'US'})])
    assert (result.created, result.pending) == (0, 1)
    assert A.SalesReceipt.query.count() == 0
    # No half-identified customer either — that is what would land in 'Unknown'
    assert A.Customer.query.filter_by(name='Unknown').count() == 0

    parked = A.PendingOrder.query.one()
    assert parked.total == pytest.approx(108.00)
    assert parked.location_hint() == 'WA, US'
    assert len(parked.items()) == 1


def test_re_delivery_updates_the_parked_row(A, ctx, processed_order):
    order = processed_order(customer_data_unavailable=True)
    _run(A, [order])
    result = _run(A, [order])

    assert A.PendingOrder.query.count() == 1
    assert result.pending == 0      # an update, not a second park


def test_a_parked_order_is_discarded_once_a_receipt_exists(A, ctx,
                                                           processed_order,
                                                           customer_id,
                                                           widget_id, make_sale):
    """Parked for missing buyer details, then entered by hand before the next
    import — without this the queue keeps asking for a sale already on the books."""
    _run(A, [processed_order(customer_data_unavailable=True)])
    assert A.PendingOrder.query.count() == 1

    make_sale(customer_id, [(widget_id, 1, 108)],
              date=A.datetime(2026, 6, 1, 10, 0),
              external_order_number='1001', source='manual')

    _run(A, [processed_order(customer_data_unavailable=True)])
    assert A.PendingOrder.query.count() == 0
    assert A.SalesReceipt.query.count() == 1


@pytest.mark.xfail(strict=True, reason=(
    'Known gap: discard_pending_order only runs when a receipt already exists. '
    'An order parked while the store withheld the buyer, then re-imported once '
    'the details are available, creates the receipt but leaves the parked row '
    'behind - completing it would write a second sale for the same order.'))
def test_supplying_details_later_clears_the_parked_row(A, ctx, processed_order):
    _run(A, [processed_order(customer_data_unavailable=True)])
    _run(A, [processed_order()])       # details available this time

    assert A.SalesReceipt.query.count() == 1
    assert A.PendingOrder.query.count() == 0


def test_completing_a_pending_order_creates_the_sale(A, ctx, client,
                                                     processed_order):
    _run(A, [processed_order(external_order_number='#PII-1',
                             customer_data_unavailable=True)])
    parked_id = A.PendingOrder.query.one().id

    response = client.post(f'/sales/pending/{parked_id}/complete', json={
        'customer': {'name': 'Named At Last', 'email': 'named@example.com',
                     'billing_address': '9 Pending Way\nOlympia, WA 98501',
                     'shipping_address': '9 Pending Way\nOlympia, WA 98501'}})
    assert response.status_code == 200, response.data

    assert A.PendingOrder.query.count() == 0
    sale = A.SalesReceipt.query.one()
    assert sale.total == Decimal('108.00')
    assert len(sale.line_items) == 1
    assert sale.receipt_number == str(sale.id)
    assert sale.external_order_number == '#PII-1'
    assert sale.customer.name == 'Named At Last'
    # And it now classifies on the tax report, which was the whole point
    assert A.get_state_info(sale.customer.shipping_address) == 'Olympia, WA 98501'


def test_completing_with_an_existing_customer(A, ctx, client, processed_order,
                                              customer_id):
    _run(A, [processed_order(customer_data_unavailable=True)])
    parked_id = A.PendingOrder.query.one().id

    response = client.post(f'/sales/pending/{parked_id}/complete',
                           json={'customer_id': customer_id})
    assert response.status_code == 200, response.data
    assert A.SalesReceipt.query.one().customer_id == customer_id
    assert A.Customer.query.count() == 1


def test_completing_without_a_customer_is_a_400(A, ctx, client, processed_order):
    _run(A, [processed_order(customer_data_unavailable=True)])
    parked_id = A.PendingOrder.query.one().id
    response = client.post(f'/sales/pending/{parked_id}/complete', json={})
    assert response.status_code == 400
    assert A.PendingOrder.query.count() == 1


def test_discarding_a_pending_order(A, ctx, client, processed_order):
    _run(A, [processed_order(customer_data_unavailable=True)])
    parked_id = A.PendingOrder.query.one().id

    assert client.post(f'/sales/pending/{parked_id}/delete').status_code == 200
    assert A.db.session.get(A.PendingOrder, parked_id) is None
    assert A.SalesReceipt.query.count() == 0


def test_the_pending_api_reports_the_queue(A, ctx, client, processed_order):
    _run(A, [processed_order(customer_data_unavailable=True)])

    assert client.get('/api/pending_orders/count').get_json()['count'] == 1
    rows = client.get('/api/pending_orders').get_json()
    assert any(row['external_order_id'] == 'EXT-1' for row in rows)


# --- Reporting --------------------------------------------------------------

def test_import_response_is_a_207_when_anything_needs_attention(A, ctx,
                                                                processed_order):
    with A.app.test_request_context('/'):
        _, status = A.import_response('Shopify', A.ImportResult(1, 0, 0, [], 0))
        assert status == 200
        _, status = A.import_response('Shopify', A.ImportResult(1, 0, 0, ['bad'], 0))
        assert status == 207
        _, status = A.import_response('Shopify', A.ImportResult(0, 0, 0, [], 1))
        assert status == 207


def test_import_response_explains_adoption_and_pending(A, ctx):
    with A.app.test_request_context('/'):
        response, _ = A.import_response('Shopify', A.ImportResult(0, 0, 2, [], 1))
        message = response.get_json()['message']
    assert 'already entered by hand' in message
    assert 'awaiting customer details' in message
