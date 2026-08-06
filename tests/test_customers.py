"""Customer CRUD, the Phase A4/A6/A7 regressions, and template escaping."""
import pytest


# --- A7: the add/edit forms used to raise KeyError on any missing field -----

def test_empty_payload_is_a_400_not_a_500(client):
    response = client.post('/customers/add', json={})
    assert response.status_code == 400
    assert response.is_json


def test_a_name_alone_is_enough(A, client):
    response = client.post('/customers/add', json={'name': 'Nameless Buyer'})
    assert response.status_code == 200, response.data
    new_id = response.get_json()['id']

    # Email is NOT NULL and unique, so a blank one gets a placeholder rather
    # than colliding with every other blank
    assert client.get(f'/customers/get/{new_id}').get_json()['email'].startswith(
        'placeholder_')


def test_two_customers_with_no_email_do_not_collide(client):
    first = client.post('/customers/add', json={'name': 'Blank One'})
    second = client.post('/customers/add', json={'name': 'Blank Two'})
    assert first.status_code == 200 and second.status_code == 200
    assert (client.get(f"/customers/get/{first.get_json()['id']}").get_json()['email']
            != client.get(f"/customers/get/{second.get_json()['id']}").get_json()['email'])


def test_editing_with_a_blank_email_keeps_a_placeholder(client):
    new_id = client.post('/customers/add', json={'name': 'Edit Me'}).get_json()['id']
    response = client.post(f'/customers/edit/{new_id}',
                           json={'name': 'Edited', 'email': ''})
    assert response.status_code == 200, response.data
    assert client.get(f'/customers/get/{new_id}').get_json()['email'].startswith(
        'placeholder_')


def test_duplicate_email_is_a_409(client, customer_id):
    response = client.post('/customers/add',
                           json={'name': 'Impostor', 'email': 'ada@example.com'})
    assert response.status_code == 409
    assert response.is_json


def test_customer_round_trips_every_field(client):
    payload = {
        'name': 'Full Record', 'company': 'Record Co',
        'email': 'full@example.com', 'email_2': 'full.alt@example.com',
        'billing_address': '1 Bill St\nOlympia, WA 98501',
        'shipping_address': '2 Ship St\nTacoma, WA 98402',
        'phone': '360-555-0199',
    }
    new_id = client.post('/customers/add', json=payload).get_json()['id']
    stored = client.get(f'/customers/get/{new_id}').get_json()
    for field, value in payload.items():
        assert stored[field] == value, field


# --- A4: merge_customers used to destroy email_2 ---------------------------

def test_merge_keeps_a_pre_existing_email_2(A, ctx):
    keeper = A.Customer(name='Merge A', email='merge-a@example.com',
                        email_2='already-here@example.com',
                        billing_address='', shipping_address='')
    other = A.Customer(name='Merge B', email='merge-b@example.com',
                       billing_address='', shipping_address='')
    A.db.session.add_all([keeper, other])
    A.db.session.commit()

    ok, message = A.merge_customers(keeper.id, other.id)
    assert ok, message
    assert keeper.email_2 == 'already-here@example.com'
    # The address that could not be kept has to be reported, not silently dropped
    assert 'merge-b@example.com' in message


def test_merge_fills_an_empty_email_2(A, ctx):
    keeper = A.Customer(name='Merge C', email='merge-c@example.com',
                        billing_address='', shipping_address='')
    other = A.Customer(name='Merge D', email='merge-d@example.com',
                       billing_address='', shipping_address='')
    A.db.session.add_all([keeper, other])
    A.db.session.commit()

    ok, _ = A.merge_customers(keeper.id, other.id)
    assert ok
    assert keeper.email_2 == 'merge-d@example.com'


def test_merge_moves_the_sales_across(A, ctx, widget_id, make_sale):
    keeper = A.Customer(name='Merge E', email='merge-e@example.com',
                        billing_address='', shipping_address='')
    other = A.Customer(name='Merge F', email='merge-f@example.com',
                       billing_address='', shipping_address='')
    A.db.session.add_all([keeper, other])
    A.db.session.commit()
    keeper_id, other_id = keeper.id, other.id
    sale_id = make_sale(other_id, [(widget_id, 1, 100)])

    A.merge_customers(keeper_id, other_id)
    assert A.db.session.get(A.SalesReceipt, sale_id).customer_id == keeper_id
    assert A.db.session.get(A.Customer, other_id) is None


def test_merging_a_customer_into_itself_is_refused(A, ctx, customer_id):
    ok, message = A.merge_customers(customer_id, customer_id)
    assert not ok
    assert message


# --- A6: address markup injection ------------------------------------------

def test_maps_query_encodes_a_multiline_address(A):
    query = A.maps_query('1 Main St\nOlympia, WA 98501')
    assert '\n' not in query
    assert '+' in query and '%2C' in query


def test_maps_query_neutralises_quotes_and_tags(A):
    query = A.maps_query('" onmouseover="alert(1)')
    assert '"' not in query and '<' not in query


def test_customer_page_escapes_an_injected_address(A, client, ctx):
    hostile = '<script>alert(1)</script>\n" onclick="steal()'
    customer = A.Customer(name='Hostile', email='hostile@example.com',
                          billing_address=hostile, shipping_address=hostile)
    A.db.session.add(customer)
    A.db.session.commit()

    body = client.get(f'/customers/view/{customer.id}').get_data(as_text=True)
    assert '<script>alert(1)</script>' not in body
    assert 'onclick="steal()' not in body
    assert '&lt;script&gt;' in body


def test_nl2br_escapes_before_it_inserts_breaks(A):
    """It used to render database content as raw HTML on every page using it."""
    rendered = str(A.nl2br('<b>bold</b>\nsecond line'))
    assert '&lt;b&gt;' in rendered
    assert '<b>' not in rendered
    assert '<br>' in rendered


def test_nl2br_handles_none(A):
    assert A.nl2br(None) == ''


# --- Deletion ---------------------------------------------------------------

def test_deleting_a_customer_with_sales_is_refused(client, customer_id,
                                                   widget_id, make_sale):
    make_sale(customer_id, [(widget_id, 1, 100)])
    response = client.post(f'/customers/delete/{customer_id}')
    assert response.status_code != 200 or not response.get_json().get('success')


def test_deleting_an_unused_customer_works(A, client, ctx):
    customer = A.Customer(name='Unused', email='unused@example.com',
                          billing_address='', shipping_address='')
    A.db.session.add(customer)
    A.db.session.commit()
    customer_id = customer.id

    assert client.post(f'/customers/delete/{customer_id}').status_code == 200
    assert A.db.session.get(A.Customer, customer_id) is None
