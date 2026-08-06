"""add_sale / edit_sale (roadmap D3) plus the A1 and A2 regressions.

Both routes share ``parse_sale_payload``. Before that they had drifted: the edit
route read ``request.form`` directly, raised KeyError on any missing field,
rejected ``$1,234.56``, accepted a quantity of zero, and — the one that actually
corrupts data — stored whatever ``total`` the client posted. The parity tests
below run the same assertions against both routes for that reason.
"""
from decimal import Decimal

import pytest


def _payload(buyer, product, **overrides):
    """A valid sale payload. Parameters are deliberately not named
    ``customer_id``/``product_id`` so an override of those keys does not collide
    with the positional arguments."""
    payload = {
        'customer_id': buyer,
        'date': '2026-08-02',
        'line_items': [{'product_id': product, 'quantity': 1,
                        'price_each': '10.00'}],
        'tax': '0', 'shipping': '0',
    }
    payload.update(overrides)
    return payload


# --- Creating ---------------------------------------------------------------

def test_add_sale_computes_the_total_itself(A, client, customer_id, widget_id,
                                            gadget_id):
    response = client.post('/sales/add', json={
        'customer_id': customer_id, 'date': '2026-08-02', 'time': '14:30',
        'line_items': [
            {'product_id': widget_id, 'quantity': 2, 'price_each': '$1,250.50'},
            {'product_id': gadget_id, 'quantity': 1, 'price_each': '10'},
        ],
        'tax': '5.00', 'shipping': '$7.14',
        'external_order_number': 'MKT-9001'})
    assert response.status_code == 200, response.data
    sale_id = response.get_json()['id']

    with A.app.app_context():
        sale = A.db.session.get(A.SalesReceipt, sale_id)
        # 2 x 1250.50 + 10 = 2511.00, + 5 tax + 7.14 shipping
        assert sale.total == Decimal('2523.14')
        assert sale.shipping == Decimal('7.14')       # '$7.14' parsed
        assert sale.tax == Decimal('5.00')
        assert len(sale.line_items) == 2


def test_add_sale_stamps_source_manual(A, client, customer_id, widget_id):
    """So a later import can recognise the receipt as the operator's."""
    sale_id = client.post('/sales/add',
                          json=_payload(customer_id, widget_id)).get_json()['id']
    with A.app.app_context():
        assert A.db.session.get(A.SalesReceipt, sale_id).source == 'manual'


def test_receipt_number_is_the_receipt_id(A, client, customer_id, widget_id):
    """Not a second copy of the marketplace order number."""
    sale_id = client.post('/sales/add', json=_payload(
        customer_id, widget_id, external_order_number='MKT-9001')).get_json()['id']
    with A.app.app_context():
        sale = A.db.session.get(A.SalesReceipt, sale_id)
        assert str(sale.receipt_number) == str(sale.id)
        assert sale.external_order_number == 'MKT-9001'


def test_date_and_time_combine(A, client, customer_id, widget_id):
    sale_id = client.post('/sales/add', json=_payload(
        customer_id, widget_id, date='2026-08-02', time='14:30')).get_json()['id']
    with A.app.app_context():
        sale = A.db.session.get(A.SalesReceipt, sale_id)
        assert (sale.date.hour, sale.date.minute) == (14, 30)


# --- Editing (D3) -----------------------------------------------------------

def test_edit_sale_takes_json_and_answers_json(A, client, customer_id, widget_id,
                                               make_sale):
    """sales.html already posted JSON here, so this path had been broken."""
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    response = client.post(f'/sales/edit/{sale_id}', json=_payload(
        customer_id, widget_id, date='2026-08-03T09:15'))

    assert response.status_code == 200, response.data
    body = response.get_json()
    assert body['success'] is True
    assert body['id'] == sale_id
    assert body['redirect'].endswith(f'/sales/view/{sale_id}')


def test_edit_ignores_a_client_supplied_total(A, client, customer_id, widget_id,
                                              make_sale):
    """The client's `total` used to be stored verbatim."""
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    client.post(f'/sales/edit/{sale_id}', json=_payload(
        customer_id, widget_id, total='999999.99',
        line_items=[{'product_id': widget_id, 'quantity': 3,
                     'price_each': '100.00'}],
        tax='1.00', shipping='2.00'))

    with A.app.app_context():
        assert A.db.session.get(A.SalesReceipt, sale_id).total == Decimal('303.00')


def test_edit_parses_a_datetime_local_value(A, client, customer_id, widget_id,
                                            make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    client.post(f'/sales/edit/{sale_id}', json=_payload(
        customer_id, widget_id, date='2026-08-03T09:15'))
    with A.app.app_context():
        sale = A.db.session.get(A.SalesReceipt, sale_id)
        assert (sale.date.hour, sale.date.minute) == (9, 15)


def test_edit_replaces_the_line_items(A, client, customer_id, widget_id,
                                      gadget_id, make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100), (gadget_id, 2, 10)])
    client.post(f'/sales/edit/{sale_id}', json=_payload(customer_id, widget_id))
    with A.app.app_context():
        items = A.db.session.get(A.SalesReceipt, sale_id).line_items
        assert len(items) == 1
        assert items[0].product_id == widget_id


def test_edit_updates_the_notes(A, client, customer_id, widget_id, make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    client.post(f'/sales/edit/{sale_id}', json=_payload(
        customer_id, widget_id, customer_notes='edited', internal_notes='private'))
    with A.app.app_context():
        sale = A.db.session.get(A.SalesReceipt, sale_id)
        assert sale.customer_notes == 'edited'
        assert sale.internal_notes == 'private'


@pytest.mark.parametrize('source', ['shopify', 'shipstation', 'manual'])
def test_edit_never_restamps_the_source(A, client, customer_id, widget_id,
                                        make_sale, source):
    """Correcting a typo must not convert an imported receipt into a manual one,
    nor strip the 'manual' that protects an adopted sale from the next import."""
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)], source=source,
                        external_order_id='EXT-9')
    client.post(f'/sales/edit/{sale_id}', json=_payload(customer_id, widget_id))
    with A.app.app_context():
        assert A.db.session.get(A.SalesReceipt, sale_id).source == source


# --- Validation parity ------------------------------------------------------

BAD_PAYLOADS = [
    ('missing customer', {'customer_id': ''}),
    ('non-numeric customer', {'customer_id': 'abc'}),
    ('missing date', {'date': ''}),
    ('unparseable date', {'date': 'not-a-date'}),
    ('no line items', {'line_items': []}),
    ('zero quantity', {'line_items': [{'product_id': 1, 'quantity': 0,
                                       'price_each': '1'}]}),
    ('negative quantity', {'line_items': [{'product_id': 1, 'quantity': -2,
                                           'price_each': '1'}]}),
    ('negative price', {'line_items': [{'product_id': 1, 'quantity': 1,
                                        'price_each': '-5'}]}),
    ('no product selected', {'line_items': [{'quantity': 1, 'price_each': '1'}]}),
    ('non-numeric tax', {'tax': 'abc'}),
    ('negative shipping', {'shipping': '-1'}),
    ('bad ship date', {'shipdate': '02/2026'}),
]


@pytest.mark.parametrize('label,override',
                         BAD_PAYLOADS, ids=[label for label, _ in BAD_PAYLOADS])
def test_add_rejects_bad_input_with_400_json(client, customer_id, widget_id,
                                             label, override):
    payload = _payload(customer_id, widget_id, **override)
    response = client.post('/sales/add', json=payload)
    assert response.status_code == 400, f'{label}: {response.status_code}'
    assert response.is_json and response.get_json()['success'] is False


@pytest.mark.parametrize('label,override',
                         BAD_PAYLOADS, ids=[label for label, _ in BAD_PAYLOADS])
def test_edit_rejects_bad_input_with_400_json(client, customer_id, widget_id,
                                              make_sale, label, override):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    payload = _payload(customer_id, widget_id, **override)
    response = client.post(f'/sales/edit/{sale_id}', json=payload)
    assert response.status_code == 400, f'{label}: {response.status_code}'
    assert response.is_json and response.get_json()['success'] is False


@pytest.mark.parametrize('route', ['add', 'edit'])
def test_an_empty_body_is_a_400(client, customer_id, widget_id, make_sale, route):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    path = '/sales/add' if route == 'add' else f'/sales/edit/{sale_id}'
    response = client.post(path, json={})
    assert response.status_code == 400
    assert response.is_json


def test_a_rejected_edit_leaves_the_sale_untouched(A, client, customer_id,
                                                   widget_id, make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 2, 100)], tax=8)
    client.post(f'/sales/edit/{sale_id}',
                json=_payload(customer_id, widget_id, tax='abc'))
    with A.app.app_context():
        sale = A.db.session.get(A.SalesReceipt, sale_id)
        assert sale.total == Decimal('208.00')
        assert len(sale.line_items) == 1


def test_money_parsing_accepts_formatted_currency(A):
    assert A._parse_money('$1,234.56', 'Total') == A.Decimal('1234.56')
    assert A._parse_money('', 'Total') == A.Decimal('0')
    assert A._parse_money(None, 'Total') == A.Decimal('0')
    with pytest.raises(ValueError):
        A._parse_money('abc', 'Total')
    with pytest.raises(ValueError):
        A._parse_money('-1', 'Total')


# --- A1: get_sale used to 500 on every call --------------------------------

def test_get_sale_returns_the_customer_contact_fields(client, customer_id,
                                                      widget_id, make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 2, 100)], tax=8, shipping=5)
    response = client.get(f'/sales/get/{sale_id}')
    assert response.status_code == 200

    body = response.get_json()
    assert body['customer_email'] == 'ada@example.com'
    assert body['customer_phone'] == '360-555-0111'
    assert body['subtotal'] == pytest.approx(200)
    assert body['total'] == pytest.approx(213)


def test_get_sale_survives_a_missing_shipdate(client, customer_id, widget_id,
                                              make_sale):
    """The guard that stopped `.strftime` being called on None."""
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    body = client.get(f'/sales/get/{sale_id}').get_json()
    assert body['shipdate'] is None


def test_get_sale_exposes_the_renamed_identifiers(client, customer_id, widget_id,
                                                  make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)],
                        external_order_number='#1797')
    body = client.get(f'/sales/get/{sale_id}').get_json()
    assert body['receipt_number'] == str(sale_id)
    assert body['external_order_number'] == '#1797'
    assert 'order_number' not in body
    assert 'shipstation_order_id' not in body


# --- A2: delete_sale used to 500 on reconciled sales -----------------------

def test_deleting_a_reconciled_sale_unlinks_the_bank_transaction(A, client,
                                                                 customer_id,
                                                                 widget_id,
                                                                 make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    with A.app.app_context():
        transaction = A.BankTransaction(
            date=A.date(2026, 5, 15), description='Deposit', amount=100.0,
            credit_debit='Credit', receipt_id=sale_id)
        A.db.session.add(transaction)
        A.db.session.commit()
        transaction_id = transaction.id

    response = client.post(f'/sales/delete/{sale_id}')
    assert response.status_code == 200, response.data
    assert 'Unlinked 1 bank transaction' in response.get_json()['message']

    with A.app.app_context():
        # The transaction is bank history and must survive; only the link goes
        transaction = A.db.session.get(A.BankTransaction, transaction_id)
        assert transaction is not None and transaction.receipt_id is None
        assert A.db.session.get(A.SalesReceipt, sale_id) is None


def test_deleting_a_sale_removes_its_line_items(A, client, customer_id,
                                                widget_id, make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    client.post(f'/sales/delete/{sale_id}')
    with A.app.app_context():
        assert A.LineItem.query.filter_by(receipt_id=sale_id).count() == 0


# --- The sales grid ---------------------------------------------------------

def test_api_sales_uses_the_renamed_keys(client, customer_id, widget_id,
                                         make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)],
                        external_order_number='#1797')
    row = next(r for r in client.get('/api/sales').get_json() if r['id'] == sale_id)
    assert row['receipt_number'] == str(sale_id)
    assert row['external_order_number'] == '#1797'
    assert 'shipstation_order_id' not in row and 'order_number' not in row


def test_money_columns_are_numbers_not_strings(client, customer_id, widget_id,
                                               make_sale):
    """'9.00' used to sort above '10.00' in the grid."""
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)], tax=8, shipping=5)
    row = next(r for r in client.get('/api/sales').get_json() if r['id'] == sale_id)
    for field in ('total', 'tax', 'shipping'):
        assert isinstance(row[field], (int, float)), field


def test_grids_bind_the_renamed_fields(client):
    """A missed Jinja reference renders as an empty string rather than erroring,
    so a botched rename would silently blank a column."""
    for path in ('/sales', '/'):
        body = client.get(path).get_data(as_text=True)
        assert 'receipt_number' in body and 'external_order_number' in body
        assert 'shipstation_order_id' not in body
        assert "field: 'order_number'" not in body
