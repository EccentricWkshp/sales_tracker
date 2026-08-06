"""Every AG Grid loads from an API endpoint, and binds fields that exist there.

Roadmap D1. Before this, customers.html and the dashboard's Recent Sales card
embedded their rows from Jinja, so the grid could only ever show the data the
page was rendered with — every edit, merge or delete needed a full reload to
look right, and the same rows were serialised two different ways.

The binding test below is the one that matters. Moving a grid onto an API turns
a name mismatch into a **silently blank column** rather than an error: AG Grid
asks each row for `params.data[field]`, gets `undefined`, and renders nothing.
That happened during this very change — the dashboard bound `customer` while
`/api/sales` sends `customer_name`.
"""
import re

import pytest

# Columns that render a button rather than a value, so they bind no data
ACTION_FIELDS = {'delete', 'edit', 'view', 'print', 'complete', 'discard'}

# template -> the endpoint whose rows it renders
GRID_SOURCES = {
    'customers.html': '/api/customers',
    'index.html': '/api/sales?limit=10',
    'sales.html': '/api/sales',
    'products.html': '/api/products',
    'pending_orders.html': '/api/pending_orders',
}


def _template(name):
    from conftest import PROJECT_ROOT
    return (PROJECT_ROOT / 'templates' / name).read_text(encoding='utf-8')


def _bound_fields(name):
    return {match for match in re.findall(r"field:\s*'([A-Za-z_][A-Za-z0-9_]*)'",
                                          _template(name))} - ACTION_FIELDS


@pytest.fixture
def populated(client, customer_id, widget_id, make_sale, A):
    """One of everything, so no endpoint answers with an empty list."""
    make_sale(customer_id, [(widget_id, 2, 100)], tax=8, shipping=5,
              external_order_number='#1001')
    with A.app.app_context():
        A.db.session.add(A.PendingOrder(
            source='shopify', external_order_id='P-1', external_order_number='#P-1',
            payload='{"items": [{"sku": "X", "quantity": 1}]}', total=10, tax=1,
            shipping=0))
        A.db.session.commit()
    return client


@pytest.mark.parametrize('template,endpoint', sorted(GRID_SOURCES.items()))
def test_every_bound_field_exists_in_the_api_payload(populated, template,
                                                     endpoint):
    rows = populated.get(endpoint).get_json()
    assert rows, f'{endpoint} returned nothing; the test cannot check {template}'

    available = set(rows[0])
    missing = _bound_fields(template) - available
    assert not missing, (
        f'{template} binds {sorted(missing)}, which {endpoint} does not send. '
        f'Those columns would render blank. Available: {sorted(available)}')


@pytest.mark.parametrize('template', ['customers.html', 'index.html'])
def test_the_grid_no_longer_embeds_rows_from_jinja(template):
    """A regression guard: putting the loop back re-creates the stale-grid bug."""
    body = _template(template)
    assert re.search(r'rowData:\s*\[\s*\]', body), \
        f'{template} should declare an empty rowData and load from its API'
    assert '{% for customer in customers %}' not in body
    assert '{% for sale in recent_sales %}' not in body


@pytest.mark.parametrize('template,endpoint', sorted(GRID_SOURCES.items()))
def test_the_template_actually_calls_its_endpoint(template, endpoint):
    body = _template(template)
    assert endpoint.split('?')[0] in body, \
        f'{template} never references {endpoint}'


# A numeric `width: 40,` used as a JS object property. The lookbehind excludes
# maxWidth/minWidth; requiring a trailing , or } excludes the CSS in these same
# files (`style="width: 100%"`, `width: '400px'`).
BARE_PIXEL_WIDTH = re.compile(r"(?<![A-Za-z])width:\s*\d+\s*[,}]")


@pytest.mark.parametrize('template', sorted(GRID_SOURCES))
def test_columns_are_sized_with_maxwidth_not_width(template):
    """Narrow columns must use `maxWidth`, never a bare numeric `width`.

    Every one of these grids sets `defaultColDef.minWidth: 100`, which clamps a
    plain `width: 40` up to 100. With rows embedded from Jinja that was hidden:
    `autoSizeStrategy: fitCellContents` measured real content at creation and
    squeezed the column back down. An API-loaded grid renders empty first, so
    there is nothing to measure and the clamp wins — which is how the customers
    grid's icon columns came out three times too wide after D1.

    Display-only, invisible to every other test here, so it gets its own rule.
    """
    offenders = BARE_PIXEL_WIDTH.findall(_template(template))
    assert not offenders, (
        f'{template} sizes a column with a bare width; use maxWidth so '
        f'defaultColDef.minWidth cannot clamp it')


# --- /api/customers ---------------------------------------------------------

def test_api_customers_is_ordered_by_name(A, client, make_customer):
    make_customer('zeta buyer', 'z@example.com')
    make_customer('Alpha Buyer', 'a@example.com')

    names = [row['name'] for row in client.get('/api/customers').get_json()]
    assert names == sorted(names, key=str.lower)


def test_api_customers_carries_the_columns_the_grid_shows(client, customer_id):
    row = next(r for r in client.get('/api/customers').get_json()
               if r['id'] == customer_id)
    for field in ('name', 'company', 'email', 'billing_address',
                  'shipping_address'):
        assert field in row, field


def test_api_customers_keeps_addresses_multiline(client, customer_id):
    """The grid flattens them for display; the modal needs the real value."""
    row = next(r for r in client.get('/api/customers').get_json()
               if r['id'] == customer_id)
    assert '\n' in row['shipping_address']


# --- /api/sales?limit= ------------------------------------------------------

def test_the_limit_returns_the_newest_rows(A, client, customer_id, widget_id,
                                           make_sale):
    for day in range(1, 6):
        make_sale(customer_id, [(widget_id, 1, 100)],
                  date=A.datetime(2026, 5, day, 12, 0))

    rows = client.get('/api/sales?limit=2').get_json()
    assert len(rows) == 2
    assert [row['date'] for row in rows] == ['05-05-2026', '05-04-2026']


def test_no_limit_returns_everything(client, customer_id, widget_id, make_sale):
    for _ in range(3):
        make_sale(customer_id, [(widget_id, 1, 100)])
    assert len(client.get('/api/sales').get_json()) == 3


def test_a_limit_larger_than_the_table_is_fine(client, customer_id, widget_id,
                                               make_sale):
    make_sale(customer_id, [(widget_id, 1, 100)])
    assert len(client.get('/api/sales?limit=500').get_json()) == 1


@pytest.mark.parametrize('value', ['abc', '1.5', ''])
def test_a_non_numeric_limit_is_a_400(client, value):
    response = client.get(f'/api/sales?limit={value}')
    if value == '':
        assert response.status_code == 200      # absent, not invalid
    else:
        assert response.status_code == 400
        assert response.is_json


def test_a_negative_limit_is_a_400(client):
    assert client.get('/api/sales?limit=-1').status_code == 400


def test_limit_zero_means_no_limit(client, customer_id, widget_id, make_sale):
    """`?limit=0` is the same as omitting it, which is what an empty form field
    would send."""
    make_sale(customer_id, [(widget_id, 1, 100)])
    assert len(client.get('/api/sales?limit=0').get_json()) == 1


# --- D2: feedback unification ----------------------------------------------

FEEDBACK_TEMPLATES = ['customers.html', 'view_customer.html', 'sales.html',
                      'products.html', 'view_sale.html']

# view_sale.html still reloads after "Update from ShipStation". That one is
# deliberate: the shipment block renders a carrier-specific tracking link
# (USPS/UPS/DHL/FedEx each have their own URL), and repainting it in JavaScript
# would mean a second copy of that mapping to keep in step with the template.
RELOAD_EXEMPT = {'view_sale.html'}


@pytest.mark.parametrize('template', FEEDBACK_TEMPLATES)
def test_no_blocking_alert_dialogs(template):
    """`alert()` blocks the page and cannot show the detail these routes return —
    a merge names the address it could not keep."""
    body = _template(template)
    assert not re.search(r'(?<![.\w])alert\s*\(', body), \
        f'{template} still calls alert(); use showFlashMessage'


@pytest.mark.parametrize('template',
                         [t for t in FEEDBACK_TEMPLATES if t not in RELOAD_EXEMPT])
def test_no_full_page_reloads_after_a_write(template):
    """A reload also rebuilds every grid on the page, discarding sorts, filters
    and scroll position."""
    body = _template(template)
    assert 'location.reload()' not in body, \
        f'{template} still reloads the page; refresh the grid or repaint in place'


@pytest.mark.parametrize('template', sorted(RELOAD_EXEMPT))
def test_the_documented_reload_exception_has_not_spread(template):
    """One reload, for the reason above. A second would mean the exemption is
    being used as a general-purpose escape hatch."""
    assert _template(template).count('location.reload()') == 1


@pytest.mark.parametrize('template', FEEDBACK_TEMPLATES)
def test_no_arbitrary_delays_before_refreshing(template):
    """The setTimeout(1500) in customers.html existed to let a since-removed
    inline banner be read, and only made the grid look stale for 1.5s."""
    body = _template(template)
    assert not re.search(r'setTimeout\([^)]*?,\s*(1500|3000)\s*\)', body), \
        f'{template} still delays its refresh'


@pytest.mark.parametrize('template', FEEDBACK_TEMPLATES)
def test_errors_are_reported_through_the_shared_helper(template):
    body = _template(template)
    assert 'showFlashMessage' in body, f'{template} reports nothing to the operator'


def test_view_customer_can_repaint_without_reloading(client, customer_id):
    """The panes need ids for applyCustomerDetails to write into."""
    body = client.get(f'/customers/view/{customer_id}').get_data(as_text=True)
    for element_id in ('detailName', 'detailEmail', 'detailEmail2',
                       'detailCompany', 'detailPhone', 'detailBillingLink',
                       'detailShippingLink'):
        assert f'id="{element_id}"' in body, element_id


def test_the_customers_page_dropped_its_dead_result_div(client):
    """#deleteResult was only ever written to by the setTimeout that is gone."""
    assert 'deleteResult' not in client.get('/customers').get_data(as_text=True)
