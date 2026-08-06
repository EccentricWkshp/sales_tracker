"""The state taxes report and the address parser it depends on.

``get_state_info``'s **return format is load-bearing**, not merely informative:
the WA B&O totals are grouped by that string. 'Olympia, WA 98501' for a
Washington address, the bare USPS code for any other US state, and the country
name otherwise. Changing the shape of any of those silently changes the totals
on a filed tax return, which is why the format is pinned here rather than just
the classification.

The parser was deliberately left unchanged when the pending-order queue was
added; these tests are what keeps it that way.
"""
import pytest


# --- The output contract ----------------------------------------------------

def test_a_washington_address_carries_city_and_zip(A):
    """WA rows are reported per city, so the city and ZIP must survive."""
    assert A.get_state_info('1 Main St\nOlympia, WA 98501') == 'Olympia, WA 98501'


def test_another_us_state_is_reported_as_the_bare_code(A):
    """Non-WA sales are one line each; the city would fragment them."""
    assert A.get_state_info('5 Elm Ave\nAustin, TX 78701') == 'TX'


def test_a_foreign_address_is_reported_as_the_country(A):
    assert A.get_state_info('10 Downing St\nLondon\nUnited Kingdom') \
        == 'United Kingdom'


def test_an_unusable_address_is_unknown_not_a_guess(A):
    assert A.get_state_info('') == 'Unknown'
    assert A.get_state_info(None) == 'Unknown'
    assert A.get_state_info('   \n  ') == 'Unknown'


def test_a_bare_state_with_no_city_stays_unknown(A):
    """The parser was deliberately not taught to read this. A half-identified
    sale would land silently in 'Unknown' and understate the WA totals, which is
    exactly why such orders are parked in the pending queue instead."""
    assert A.get_state_info(', CA') == 'Unknown'


# --- Parsing variations seen in the live data ------------------------------

@pytest.mark.parametrize('address,expected', [
    ('1 Main St\nOlympia, WA 98501', 'Olympia, WA 98501'),
    ('1 Main St\nOlympia, WA 98501-1234', 'Olympia, WA 98501-1234'),
    ('1 Main St\nOlympia, Washington 98501', 'Olympia, WA 98501'),
    ('1 Main St\nOlympia WA 98501', 'Olympia, WA 98501'),
    ('1 Main St\nOlympia, WA\n98501', 'Olympia, WA 98501'),
    ('1 Main St\nOlympia, WA 98501\nUnited States', 'Olympia, WA 98501'),
])
def test_washington_address_shapes(A, address, expected):
    assert A.get_state_info(address) == expected


@pytest.mark.parametrize('address,expected', [
    ('5 Elm Ave\nAustin, TX 78701', 'TX'),
    ('5 Elm Ave\nLebanon TN 37087', 'TN'),
    ('5 Elm Ave\nFairview, TX', 'TX'),
    ('5 Elm Ave\nAustin, Texas 78701', 'TX'),
])
def test_other_state_shapes(A, address, expected):
    assert A.get_state_info(address) == expected


def test_a_spelled_out_state_is_not_confused_with_a_country(A):
    """'Tbilisi, Georgia' must not become GA. A spelled-out region with no ZIP
    and no United States line stays a country."""
    assert A.get_state_info('Tbilisi\nGeorgia') == 'Georgia'
    assert A.get_state_info('Georgia') == 'Georgia'


def test_a_street_line_ending_in_a_direction_is_not_read_as_a_state(A):
    """Which is why the no-comma pattern requires a ZIP."""
    assert A.get_state_info('123 Cedar Ave NE\nOlympia, WA 98501') \
        == 'Olympia, WA 98501'


# --- format_address feeds the parser ---------------------------------------

@pytest.mark.parametrize('data,expected', [
    ({'street1': '123 Main St', 'city': 'Olympia', 'state': 'WA',
      'postal_code': '98501', 'country': 'US'}, 'Olympia, WA 98501'),
    ({'street1': '5 Elm Ave', 'city': 'Austin', 'state': 'TX',
      'postal_code': '78701', 'country': 'US'}, 'TX'),
])
def test_a_formatted_address_round_trips_through_the_parser(A, data, expected):
    """The importers build the address with format_address and the report reads
    it back with get_state_info; the pair has to agree."""
    assert A.get_state_info(A.format_address(data)) == expected


def test_format_address_does_not_produce_a_bare_comma_state(A):
    """When a platform withholds street/city/ZIP this must not degrade to
    ', CA', which the parser cannot read."""
    formatted = A.format_address({'city': '', 'state': 'CA', 'postal_code': '',
                                  'country': 'US'})
    assert not formatted.startswith(',')


# --- The report itself ------------------------------------------------------

@pytest.fixture
def quarter_of_sales(A, customer_id, widget_id, gadget_id, make_customer,
                     make_sale):
    """Three Q2 sales plus one outside the quarter."""
    out_of_state = make_customer('Texan Buyer', 'tx@example.com',
                                 shipping_address='5 Elm Ave\nAustin, TX 78701',
                                 billing_address='5 Elm Ave\nAustin, TX 78701')
    return {
        'wa': make_sale(customer_id, [(widget_id, 2, 100)], tax=16, shipping=5,
                        date=A.datetime(2026, 4, 10, 9, 0)),
        'wa_mixed': make_sale(customer_id, [(widget_id, 1, 100), (gadget_id, 3, 10)],
                              tax=10, shipping=0,
                              date=A.datetime(2026, 6, 30, 23, 59)),
        'tx': make_sale(out_of_state, [(gadget_id, 1, 10)],
                        date=A.datetime(2026, 5, 1, 12, 0)),
        'next_quarter': make_sale(customer_id, [(widget_id, 1, 100)],
                                  date=A.datetime(2026, 7, 1, 0, 0)),
    }


def _rows(client, year=2026, quarter='Q2'):
    response = client.get(f'/api/state_taxes_data?year={year}&quarter={quarter}')
    assert response.status_code == 200
    return response.get_json()


def test_the_quarter_boundary_is_half_open(client, quarter_of_sales):
    """A sale at 23:59 on the last day belongs to the quarter; one at midnight
    the next day does not."""
    body = _rows(client)
    ids = {row['id'] for row in body['rows']}
    assert quarter_of_sales['wa_mixed'] in ids
    assert quarter_of_sales['next_quarter'] not in ids
    assert body['lastRow'] == 3


def test_each_row_reports_the_state_string_the_totals_group_on(client,
                                                               quarter_of_sales):
    rows = {row['id']: row for row in _rows(client)['rows']}
    assert rows[quarter_of_sales['wa']]['state'] == 'Olympia, WA 98501'
    assert rows[quarter_of_sales['tx']]['state'] == 'TX'


def test_manufacturing_is_split_out_of_retail(client, quarter_of_sales):
    """WA B&O taxes manufacturing separately; `retail` is the whole subtotal and
    `manufacturing` the part from is_manufactured products."""
    rows = {row['id']: row for row in _rows(client)['rows']}

    # WIDGET-1 is manufactured, GADGET-1 is not: 100 + 30 subtotal, 100 of it
    # manufactured
    mixed = rows[quarter_of_sales['wa_mixed']]
    assert mixed['retail'] == pytest.approx(130)
    assert mixed['manufacturing'] == pytest.approx(100)

    # A sale with no manufactured products reports zero, not the subtotal
    assert rows[quarter_of_sales['tx']]['manufacturing'] == pytest.approx(0)


def test_the_row_basis_excludes_tax(client, quarter_of_sales):
    """`retail` is the line-item subtotal; tax is not revenue and shipping is
    reported in its own column."""
    row = next(r for r in _rows(client)['rows']
               if r['id'] == quarter_of_sales['wa'])
    assert row['retail'] == pytest.approx(200)     # not 216, not 221
    assert row['shipping'] == pytest.approx(5)


def test_totals_reconcile_against_the_receipts(A, client, quarter_of_sales):
    """The number that actually goes on the return."""
    rows = _rows(client)['rows']
    wa_retail = sum(row['retail'] for row in rows if row['state'].endswith('98501'))
    assert wa_retail == pytest.approx(330)      # 200 + 130

    with A.app.app_context():
        expected = sum(
            item.total_price
            for sale in A.SalesReceipt.query.filter(
                A.SalesReceipt.date >= A.datetime(2026, 4, 1),
                A.SalesReceipt.date < A.datetime(2026, 7, 1)).all()
            for item in sale.line_items
            if A.get_state_info(sale.customer.shipping_address).endswith('98501'))
    assert wa_retail == pytest.approx(float(expected))


def test_paging_does_not_change_the_reported_total(client, quarter_of_sales):
    """`lastRow` must cover the whole quarter even when a page is requested, or
    the report footer would total only what is on screen."""
    page = client.get(
        '/api/state_taxes_data?year=2026&quarter=Q2&start=0&end=2').get_json()
    assert len(page['rows']) == 2
    assert page['lastRow'] == 3


@pytest.mark.parametrize('quarter,month', [('Q1', 1), ('Q2', 4), ('Q3', 7),
                                           ('Q4', 10)])
def test_every_quarter_selects_its_own_months(A, client, customer_id, widget_id,
                                              make_sale, quarter, month):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)],
                        date=A.datetime(2026, month, 15, 12, 0))
    ids = {row['id'] for row in _rows(client, quarter=quarter)['rows']}
    assert sale_id in ids
    # And no other quarter claims it
    others = {q for q in ('Q1', 'Q2', 'Q3', 'Q4') if q != quarter}
    for other in others:
        assert sale_id not in {row['id'] for row in _rows(client, quarter=other)['rows']}


def test_q4_rolls_into_the_next_year(A, client, customer_id, widget_id,
                                     make_sale):
    """The end of Q4 is 1 January, not month 13."""
    inside = make_sale(customer_id, [(widget_id, 1, 100)],
                       date=A.datetime(2026, 12, 31, 23, 59))
    outside = make_sale(customer_id, [(widget_id, 1, 100)],
                        date=A.datetime(2027, 1, 1, 0, 0))
    ids = {row['id'] for row in _rows(client, quarter='Q4')['rows']}
    assert inside in ids and outside not in ids
