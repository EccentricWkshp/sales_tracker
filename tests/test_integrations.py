"""The integration registry and the Management page it drives (roadmap E7/E8).

``INTEGRATIONS`` is the single source of truth for every order source: the
Management form, the "from environment" badges, the dashboard cards, the fetch
routes and the OAuth round trip are all generated from it. These tests assert
that the generation actually reaches each of those places, so a platform added
to the registry cannot be half-wired.
"""
import pytest

EXPECTED_KEYS = {'shopify', 'shipstation', 'shippo', 'woocommerce', 'etsy', 'ebay'}


def test_every_platform_is_registered(A):
    assert set(A.INTEGRATIONS) == EXPECTED_KEYS


def test_the_registry_key_is_the_source_value(A):
    for key, spec in A.INTEGRATIONS.items():
        assert spec.key == key


@pytest.mark.parametrize('key', sorted(EXPECTED_KEYS - {'woocommerce'}))
def test_each_platform_has_an_importer(A, key):
    spec = A.INTEGRATIONS[key]
    assert spec.fetch is not None and spec.process is not None


def test_woocommerce_is_declared_without_an_importer(A):
    """The route exists as a 501 stub; the registry must say so rather than
    offering a card that cannot work."""
    assert A.INTEGRATIONS['woocommerce'].fetch is None


def test_only_the_marketplaces_use_oauth(A):
    with_oauth = {key for key, spec in A.INTEGRATIONS.items() if spec.oauth}
    assert with_oauth == {'etsy', 'ebay'}


def test_secret_fields_are_declared_for_every_platform(A):
    for key, spec in A.INTEGRATIONS.items():
        assert spec.secret_fields, f'{key} declares no secret fields'
        # A field cannot be both hidden and rendered
        assert not set(spec.secret_fields) & set(spec.plain_fields), key


@pytest.mark.parametrize('rule', [
    '/integrations/<key>/fetch_orders',
    '/integrations/<key>/connect',
    '/integrations/<key>/paste_code',
    '/integrations/<key>/disconnect',
    '/etsy/callback', '/ebay/callback',
    '/etsy/fetch_orders', '/ebay/fetch_orders',
    '/shopify/fetch_orders', '/shippo/fetch_orders', '/shipstation/fetch_orders',
])
def test_route_exists(A, rule):
    """The per-platform routes remain as thin aliases so existing URLs work."""
    assert rule in {str(r) for r in A.app.url_map.iter_rules()}


# --- Management page --------------------------------------------------------

def test_management_renders_a_tab_per_platform(A, client):
    html = client.get('/management').get_data(as_text=True)
    for key in A.INTEGRATIONS:
        assert f'data-tab="{key}"' in html, key
        assert f'id="tab-{key}"' in html, key
    assert 'data-tab="company"' in html


def test_saving_credentials_through_the_registry(A, client):
    response = client.post('/management', data={
        'name': 'Test Co', 'address': '1 Way', 'phone': '360-555-0100',
        'email': 'sales@example.com',
        'etsy_enabled': 'on', 'etsy_client_id': 'ETSYKEY',
        'etsy_client_secret': 'ETSYSECRET', 'etsy_shop_id': '12345',
        'ebay_enabled': 'on', 'ebay_client_id': 'EBAYAPP',
        'ebay_client_secret': 'EBAYCERT', 'ebay_ru_name': 'My-RuName',
        'ebay_sandbox': 'on',
    }, follow_redirects=True)
    assert response.status_code == 200

    with A.app.app_context():
        etsy = A.EtsyCredentials.query.one()
        ebay = A.EbayCredentials.query.one()
        assert etsy.client_id == 'ETSYKEY' and etsy.shop_id == '12345'
        assert etsy.enabled is True
        assert ebay.client_id == 'EBAYAPP' and ebay.ru_name == 'My-RuName'
        assert ebay.sandbox is True


def test_a_blank_secret_means_leave_unchanged(A, client):
    """Secrets render blank with a "saved" badge, so a blank submit must not
    wipe them."""
    client.post('/management', data={
        'name': 'Test Co', 'etsy_enabled': 'on', 'etsy_client_id': 'ETSYKEY',
        'etsy_client_secret': 'ETSYSECRET', 'etsy_shop_id': '12345'},
        follow_redirects=True)

    client.post('/management', data={
        'name': 'Test Co', 'etsy_enabled': 'on', 'etsy_client_id': '',
        'etsy_shop_id': '12345'}, follow_redirects=True)

    with A.app.app_context():
        assert A.EtsyCredentials.query.one().client_id == 'ETSYKEY'


def test_a_plain_field_is_cleared_by_a_blank_submit(A, client):
    """Unlike secrets, plain fields round-trip through the page, so a blank one
    is the operator deleting it."""
    client.post('/management', data={
        'name': 'Test Co', 'etsy_enabled': 'on', 'etsy_client_id': 'K',
        'etsy_shop_id': '12345'}, follow_redirects=True)
    client.post('/management', data={
        'name': 'Test Co', 'etsy_enabled': 'on', 'etsy_shop_id': ''},
        follow_redirects=True)

    with A.app.app_context():
        assert A.EtsyCredentials.query.one().shop_id == ''


def test_an_omitted_checkbox_turns_the_integration_off(A, client):
    """An unchecked box submits nothing, which is what the real page posts."""
    client.post('/management', data={'name': 'Test Co', 'ebay_enabled': 'on',
                                     'ebay_client_id': 'EBAYAPP'},
                follow_redirects=True)
    client.post('/management', data={'name': 'Test Co'}, follow_redirects=True)

    with A.app.app_context():
        assert A.EbayCredentials.query.one().enabled is False


def test_changing_the_app_identity_forces_a_reconnect(A, client):
    """New client credentials mean the stored tokens no longer belong to them."""
    client.post('/management', data={
        'name': 'Test Co', 'etsy_enabled': 'on', 'etsy_client_id': 'KEY1',
        'etsy_client_secret': 'SECRET1'}, follow_redirects=True)
    with A.app.app_context():
        etsy = A.EtsyCredentials.query.one()
        etsy.access_token, etsy.refresh_token = 'AT', 'RT'
        etsy.access_token_expires_at = A.datetime.now() + A.timedelta(hours=1)
        A.db.session.commit()

    client.post('/management', data={
        'name': 'Test Co', 'etsy_enabled': 'on', 'etsy_client_id': 'KEY2',
        'etsy_client_secret': 'SECRET2'}, follow_redirects=True)

    with A.app.app_context():
        etsy = A.EtsyCredentials.query.one()
        assert etsy.access_token == '' and etsy.refresh_token == ''
        assert etsy.access_token_expires_at is None


def test_no_stored_secret_is_rendered_into_the_page(A, client):
    """B6: credentials must never round-trip through the page HTML."""
    client.post('/management', data={
        'name': 'Test Co', 'etsy_enabled': 'on',
        'etsy_client_id': 'ZZ-KEYSTRING-ZZ', 'etsy_client_secret': 'ZZ-SHARED-ZZ',
        'ebay_client_id': 'ZZ-APPID-ZZ', 'ebay_client_secret': 'ZZ-CERTID-ZZ',
    }, follow_redirects=True)

    html = client.get('/management').get_data(as_text=True)
    for secret in ('ZZ-KEYSTRING-ZZ', 'ZZ-SHARED-ZZ', 'ZZ-APPID-ZZ',
                   'ZZ-CERTID-ZZ'):
        assert secret not in html, secret
    assert 'leave blank to keep' in html.lower()


def test_a_plain_field_is_shown_back(A, client):
    """Shop ids and domains are not secret, and hiding them would make the form
    unusable."""
    client.post('/management', data={'name': 'Test Co', 'etsy_enabled': 'on',
                                     'etsy_shop_id': '55512345'},
                follow_redirects=True)
    assert '55512345' in client.get('/management').get_data(as_text=True)


def test_management_marks_a_field_supplied_by_the_environment(A, client,
                                                              monkeypatch):
    """So it is clear why editing the field does nothing."""
    monkeypatch.setenv('ETSY_KEYSTRING', 'from-the-environment')
    views = {view['key']: view for view in _views(A, client)}
    assert views['etsy']['from_env']['client_id'] is True
    assert views['etsy']['from_env']['client_secret'] is False


def _views(A, client):
    with A.app.test_request_context('/'):
        return A.integration_views()


def test_integration_views_never_carry_a_secret_value(A, client):
    client.post('/management', data={
        'name': 'Test Co', 'etsy_client_id': 'ZZ-KEYSTRING-ZZ',
        'etsy_client_secret': 'ZZ-SHARED-ZZ'}, follow_redirects=True)

    rendered = repr(_views(A, client))
    assert 'ZZ-KEYSTRING-ZZ' not in rendered
    assert 'ZZ-SHARED-ZZ' not in rendered


def test_field_labels_use_each_platforms_own_words(A):
    """Storage is generic (client_id/client_secret); the operator sees the names
    from their developer console."""
    etsy = A.INTEGRATIONS['etsy']
    assert etsy.label_for('client_id') == 'Keystring'
    assert etsy.label_for('client_secret') == 'Shared Secret'

    ebay = A.INTEGRATIONS['ebay']
    assert ebay.label_for('client_id') == 'App ID (Client ID)'
    assert ebay.label_for('client_secret') == 'Cert ID (Client Secret)'

    # A platform that declares nothing still gets a readable label
    assert A.INTEGRATIONS['shopify'].label_for('shop_domain') == 'Shop Domain'


# --- Dashboard cards --------------------------------------------------------

def test_dashboard_cards_follow_the_registry(A, client):
    assert b'/integrations/etsy/fetch_orders' not in client.get('/').data

    client.post('/management', data={'name': 'Test Co', 'etsy_enabled': 'on',
                                     'etsy_client_id': 'K'},
                follow_redirects=True)

    body = client.get('/').data
    assert b'/integrations/etsy/fetch_orders' in body
    # Everything still off stays off the dashboard
    assert b'/integrations/shippo/fetch_orders' not in body


# --- Fetch route guards -----------------------------------------------------

def test_an_unknown_platform_404s(client):
    response = client.post('/integrations/nope/fetch_orders',
                           data={'start_date': '2026-01-01',
                                 'end_date': '2026-01-02'})
    assert response.status_code == 404


def test_woocommerce_reports_that_it_is_not_implemented(client):
    response = client.post('/integrations/woocommerce/fetch_orders',
                           data={'start_date': '2026-01-01',
                                 'end_date': '2026-01-02'})
    assert response.status_code == 501


@pytest.mark.parametrize('key', sorted(EXPECTED_KEYS - {'woocommerce'}))
def test_a_disabled_platform_refuses_before_any_outbound_call(client, key):
    response = client.post(f'/integrations/{key}/fetch_orders',
                           data={'start_date': '2026-01-01',
                                 'end_date': '2026-01-02'})
    assert response.status_code == 400


@pytest.mark.parametrize('data,label', [
    ({'start_date': 'bad', 'end_date': 'also-bad'}, 'unparseable'),
    ({'start_date': '2026-02-01', 'end_date': '2026-01-01'}, 'reversed'),
    ({'start_date': '2026-01-01'}, 'missing end'),
    ({}, 'missing both'),
])
def test_a_bad_date_range_is_a_400(A, client, data, label):
    client.post('/management', data={'name': 'Test Co', 'etsy_enabled': 'on',
                                     'etsy_client_id': 'K'},
                follow_redirects=True)
    response = client.post('/integrations/etsy/fetch_orders', data=data)
    assert response.status_code == 400, label


def test_the_legacy_per_platform_route_still_works(client):
    """Existing URLs must keep working after the move to the generic route."""
    legacy = client.post('/etsy/fetch_orders',
                         data={'start_date': '2026-01-01',
                               'end_date': '2026-01-02'})
    generic = client.post('/integrations/etsy/fetch_orders',
                          data={'start_date': '2026-01-01',
                                'end_date': '2026-01-02'})
    assert legacy.status_code == generic.status_code == 400
