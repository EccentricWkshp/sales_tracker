"""Money is stored as Numeric, not Float (roadmap E4).

Binary floating point cannot hold 0.10, 0.20 or 19.99. Under `Float` a receipt
whose parts were 19.99 + 5.00 + 1.90 stored as 26.889999999999997, and the state
taxes report — which sums `line_item.total_price` across a whole quarter — drifted
further with every row. Nothing ever *displayed* wrongly, because every template
formats with `%.2f`; the stored figure simply was not the figure.

These tests pin the three things that follow from the column type: values
round-trip exactly, sums are exact, and the JSON boundary still emits numbers
rather than Decimals or strings.
"""
import runpy
import sqlite3
import sys
from decimal import Decimal

import pytest

MONEY_COLUMNS = [
    ('SalesReceipt', 'total'), ('SalesReceipt', 'tax'), ('SalesReceipt', 'shipping'),
    ('LineItem', 'price_each'), ('LineItem', 'total_price'),
    ('BankTransaction', 'amount'),
]


# --- The column type itself -------------------------------------------------

@pytest.mark.parametrize('model_name,column', MONEY_COLUMNS,
                         ids=[f'{m}.{c}' for m, c in MONEY_COLUMNS])
def test_the_column_is_numeric_with_two_decimal_places(A, model_name, column):
    import sqlalchemy

    model = getattr(A, model_name)
    kind = model.__table__.columns[column].type
    assert isinstance(kind, sqlalchemy.Numeric)
    assert not isinstance(kind, sqlalchemy.Float), f'{model_name}.{column} is still Float'
    assert (kind.precision, kind.scale) == (10, 2)


@pytest.mark.parametrize('model_name,column', MONEY_COLUMNS,
                         ids=[f'{m}.{c}' for m, c in MONEY_COLUMNS])
def test_reading_a_money_column_gives_a_decimal(A, ctx, customer_id, widget_id,
                                                make_sale, model_name, column):
    make_sale(customer_id, [(widget_id, 1, Decimal('19.99'))],
              tax=Decimal('1.90'), shipping=Decimal('5.00'))
    A.db.session.add(A.BankTransaction(date=A.date(2026, 5, 1), description='x',
                                       amount=Decimal('26.89'),
                                       credit_debit='Credit'))
    A.db.session.commit()

    row = getattr(A, model_name).query.first()
    assert isinstance(getattr(row, column), Decimal)


# --- Exactness --------------------------------------------------------------

def test_a_total_that_float_could_not_hold(A, ctx, client, customer_id, widget_id):
    """19.99 + 5.00 + 1.90 stored as 26.889999999999997 under Float."""
    response = client.post('/sales/add', json={
        'customer_id': customer_id, 'date': '2026-05-01',
        'line_items': [{'product_id': widget_id, 'quantity': 1,
                        'price_each': '19.99'}],
        'tax': '1.90', 'shipping': '5.00'})
    assert response.status_code == 200

    sale = A.db.session.get(A.SalesReceipt, response.get_json()['id'])
    assert sale.total == Decimal('26.89')
    # The distinction the whole change exists for: exactly equal, not merely close
    assert str(sale.total) == '26.89'


def test_a_quantity_price_product_stays_exact(A, ctx, client, customer_id,
                                              widget_id):
    """3 x 0.10 is 0.30, not 0.30000000000000004."""
    response = client.post('/sales/add', json={
        'customer_id': customer_id, 'date': '2026-05-01',
        'line_items': [{'product_id': widget_id, 'quantity': 3,
                        'price_each': '0.10'}],
        'tax': '0', 'shipping': '0'})
    sale = A.db.session.get(A.SalesReceipt, response.get_json()['id'])
    assert sale.line_items[0].total_price == Decimal('0.30')
    assert sale.total == Decimal('0.30')


def test_summing_many_line_items_does_not_drift(A, ctx, customer_id, widget_id,
                                                make_sale):
    """The state taxes report sums a whole quarter. Under Float, 1000 rows of
    0.10 summed to 99.99999999999859."""
    make_sale(customer_id, [(widget_id, 1, Decimal('0.10'))] * 1000)

    sale = A.SalesReceipt.query.one()
    assert sum(item.total_price for item in sale.line_items) == Decimal('100.00')


def test_the_sql_sum_is_exact_too(A, ctx, customer_id, widget_id, make_sale):
    """The dashboard's revenue card sums in SQL rather than in Python."""
    for _ in range(10):
        make_sale(customer_id, [(widget_id, 1, Decimal('19.99'))],
                  tax=Decimal('1.90'), shipping=Decimal('5.00'))

    total = A.db.session.query(A.func.sum(A.SalesReceipt.total)).scalar()
    assert total == Decimal('268.90')


def test_an_imported_order_stores_the_decimal_it_was_given(A, ctx,
                                                           processed_order):
    """replace_line_items used to cast to float on the way in, reintroducing the
    error the column type exists to avoid."""
    A.import_processed_orders([processed_order(
        items=[{'sku': 'WIDGET-1', 'name': 'w', 'quantity': 3,
                'unit_price': Decimal('19.99')}],
        order_total=Decimal('59.97'), tax_amount=Decimal('0'),
        shipping_amount=Decimal('0'))], 'shopify')

    item = A.SalesReceipt.query.one().line_items[0]
    assert item.price_each == Decimal('19.99')
    assert item.total_price == Decimal('59.97')


def test_editing_a_sale_keeps_the_figures_exact(A, ctx, client, customer_id,
                                                widget_id, make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    client.post(f'/sales/edit/{sale_id}', json={
        'customer_id': customer_id, 'date': '2026-05-01',
        'line_items': [{'product_id': widget_id, 'quantity': 7,
                        'price_each': '1.15'}],
        'tax': '0.81', 'shipping': '4.20'})

    sale = A.db.session.get(A.SalesReceipt, sale_id)
    assert sale.total == Decimal('13.06')      # 8.05 + 0.81 + 4.20


# --- The JSON boundary ------------------------------------------------------

def test_the_grid_still_receives_numbers(client, customer_id, widget_id,
                                         make_sale):
    """Decimal is not JSON serialisable, and a string would break
    agNumberColumnFilter — '9.00' used to sort above '10.00'."""
    sale_id = make_sale(customer_id, [(widget_id, 1, Decimal('19.99'))],
                        tax=Decimal('1.90'), shipping=Decimal('5.00'))
    row = next(r for r in client.get('/api/sales').get_json() if r['id'] == sale_id)

    for field in ('total', 'tax', 'shipping'):
        assert isinstance(row[field], (int, float)), f'{field} is {type(row[field])}'
        assert not isinstance(row[field], str)
    assert row['total'] == 26.89


def test_line_item_json_is_numeric_too(client, customer_id, widget_id, make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 2, Decimal('19.99'))])
    row = next(r for r in client.get('/api/sales').get_json() if r['id'] == sale_id)
    item = row['line_items'][0]
    assert isinstance(item['price_each'], (int, float))
    assert isinstance(item['total_price'], (int, float))


@pytest.mark.parametrize('path', [
    '/api/sales', '/api/transactions', '/api/state_taxes_data?year=2026&quarter=Q2',
])
def test_money_endpoints_serialise(client, customer_id, widget_id, make_sale,
                                   path):
    """A Decimal leaking into a response raises at serialisation time, so a 200
    is the assertion here."""
    make_sale(customer_id, [(widget_id, 1, Decimal('19.99'))], tax=Decimal('1.90'))
    assert client.get(path).status_code == 200


def test_get_sale_subtotal_is_computed_in_decimal(client, customer_id, widget_id,
                                                  make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, Decimal('19.99'))],
                        tax=Decimal('1.90'), shipping=Decimal('5.00'))
    body = client.get(f'/sales/get/{sale_id}').get_json()
    assert body['subtotal'] == 19.99
    assert body['total'] == 26.89


# --- Bank transactions ------------------------------------------------------

def test_the_bank_csv_parses_decimals(A, ctx, client):
    csv = ('Booking Date,Description,Amount,Credit Debit Indicator,type,'
           'Category,Check Serial Number\n'
           '05/01/2026,Deposit,"$1,234.56",Credit,ACH Credit,Sales,\n')
    response = client.post('/finance/upload_transactions',
                           data={'file': (_bytes(csv), 'txns.csv')},
                           content_type='multipart/form-data')
    assert response.status_code == 200, response.data

    transaction = A.BankTransaction.query.one()
    assert transaction.amount == Decimal('1234.56')
    assert isinstance(transaction.amount, Decimal)


def test_duplicate_detection_compares_amounts_exactly(A, ctx, client):
    """`==` between two floats that merely display the same is meaningless."""
    header = ('Booking Date,Description,Amount,Credit Debit Indicator,type,'
              'Category,Check Serial Number\n')
    row = '05/01/2026,Coffee,19.99,Debit,POS,Meals,\n'

    client.post('/finance/upload_transactions',
                data={'file': (_bytes(header + row), 'a.csv')},
                content_type='multipart/form-data')
    response = client.post('/finance/upload_transactions',
                           data={'file': (_bytes(header + row), 'b.csv')},
                           content_type='multipart/form-data')

    assert A.BankTransaction.query.count() == 1
    assert 'Skipped 1 duplicate' in response.get_json()['message']


def test_a_different_amount_is_not_a_duplicate(A, ctx, client):
    header = ('Booking Date,Description,Amount,Credit Debit Indicator,type,'
              'Category,Check Serial Number\n')
    client.post('/finance/upload_transactions', content_type='multipart/form-data',
                data={'file': (_bytes(header + '05/01/2026,Coffee,19.99,Debit,POS,Meals,\n'),
                               'a.csv')})
    client.post('/finance/upload_transactions', content_type='multipart/form-data',
                data={'file': (_bytes(header + '05/01/2026,Coffee,19.98,Debit,POS,Meals,\n'),
                               'b.csv')})
    assert A.BankTransaction.query.count() == 2


def _bytes(text):
    import io
    return io.BytesIO(text.encode('utf-8'))


# --- The migration ----------------------------------------------------------

@pytest.fixture
def drifted_db(A, tmp_path):
    """A copy of the test database carrying the float artefacts E4 cleans up."""
    target = tmp_path / 'drifted.db'
    source = sqlite3.connect(A.configured_sqlite_path())
    try:
        destination = sqlite3.connect(str(target))
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()

    conn = sqlite3.connect(str(target))
    try:
        conn.execute("DELETE FROM line_item")
        conn.execute("DELETE FROM bank_transaction")
        conn.execute("DELETE FROM sales_receipt")
        conn.execute(
            "INSERT INTO sales_receipt (id, customer_id, date, total, tax, shipping) "
            "VALUES (1, (SELECT id FROM customer LIMIT 1), '2026-05-01 00:00:00', "
            "26.889999999999997, 1.9000000000000001, 5.0)")
        conn.execute(
            "INSERT INTO line_item (id, receipt_id, product_id, quantity, "
            "price_each, total_price) VALUES (1, 1, (SELECT id FROM product LIMIT 1), "
            "3, 0.1, 0.30000000000000004)")
        conn.execute(
            "INSERT INTO bank_transaction (id, date, description, amount, "
            "credit_debit) VALUES (1, '2026-05-01', 'Coffee', 19.989999999999998, "
            "'Debit')")
        conn.commit()
    finally:
        conn.close()
    return target


def _run_migration(path):
    argv = sys.argv
    sys.argv = ['money_columns_to_numeric.py', str(path)]
    try:
        runpy.run_path(
            str(__import__('pathlib').Path(__file__).parent.parent
                / 'migrations' / 'money_columns_to_numeric.py'),
            run_name='__main__')
    finally:
        sys.argv = argv


def _values(path):
    conn = sqlite3.connect(str(path))
    try:
        return {
            'receipt': conn.execute(
                "SELECT total, tax, shipping FROM sales_receipt").fetchone(),
            'item': conn.execute(
                "SELECT price_each, total_price FROM line_item").fetchone(),
            'amount': conn.execute(
                "SELECT amount FROM bank_transaction").fetchone()[0],
        }
    finally:
        conn.close()


def test_the_migration_rounds_drifted_values(drifted_db, capsys):
    before = _values(drifted_db)
    assert before['receipt'][0] != 26.89        # the artefact is really there

    _run_migration(drifted_db)

    after = _values(drifted_db)
    assert after['receipt'] == (26.89, 1.90, 5.00)
    assert after['item'] == (0.10, 0.30)
    assert after['amount'] == 19.99


def test_the_migration_is_idempotent(drifted_db, capsys):
    _run_migration(drifted_db)
    first = _values(drifted_db)
    _run_migration(drifted_db)
    assert _values(drifted_db) == first

    # And says so rather than reporting phantom work on the second run
    assert 'already clean' in capsys.readouterr().out


def test_the_migration_leaves_a_discounted_receipt_alone(drifted_db, capsys):
    """A total below line items + tax + shipping is a discount or customer
    credit — the total is what was actually charged, and it is authoritative.
    The migration counts these so a large jump is noticeable, and changes none
    of them."""
    _run_migration(drifted_db)
    output = capsys.readouterr().out
    # 0.30 of line items + 1.90 tax + 5.00 shipping is 7.20, not 26.89
    assert 'discount or customer credit' in output

    # The stored total is left exactly as it was, only rounded to the cent
    assert _values(drifted_db)['receipt'][0] == 26.89


def test_the_migration_refuses_a_database_that_is_not_ours(tmp_path):
    stranger = tmp_path / 'stranger.db'
    conn = sqlite3.connect(str(stranger))
    conn.execute('CREATE TABLE sales_receipt (id INTEGER PRIMARY KEY)')
    conn.commit()
    conn.close()

    with pytest.raises(SystemExit, match='missing'):
        _run_migration(stranger)


def test_the_migration_refuses_a_missing_file(tmp_path):
    with pytest.raises(SystemExit, match='not found'):
        _run_migration(tmp_path / 'nope.db')
