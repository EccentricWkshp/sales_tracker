"""The shared OAuth 2.0 consent round trip used by Etsy and eBay.

All transport is mocked. What is being tested is the machinery: PKCE, the
one-shot state nonce, which credentials go in the header versus the body, token
caching and refresh, and the paste-code fallback that exists because a LAN-only
box cannot always receive the redirect.
"""
from unittest import mock

import pytest

BASE_URL = 'http://192.168.1.194:4444'


@pytest.fixture
def etsy(A):
    with A.app.app_context():
        credentials = A.EtsyCredentials(client_id='ETSYKEY',
                                        client_secret='ETSYSECRET',
                                        shop_id='12345', enabled=True)
        A.db.session.add(credentials)
        A.db.session.commit()
        return credentials.id


@pytest.fixture
def ebay(A):
    with A.app.app_context():
        credentials = A.EbayCredentials(client_id='EBAYAPP',
                                        client_secret='EBAYCERT',
                                        ru_name='My-RuName', sandbox=True,
                                        enabled=True)
        A.db.session.add(credentials)
        A.db.session.commit()
        return credentials.id


def token_response(payload):
    response = mock.Mock()
    response.status_code, response.ok, response.headers = 200, True, {}
    response.json.return_value = payload
    return response


# --- Building the authorize URL --------------------------------------------

def test_etsy_authorize_url_carries_pkce(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        url = A.oauth_begin(A.INTEGRATIONS['etsy'], credentials)

        assert url.startswith('https://www.etsy.com/oauth/connect?')
        assert 'code_challenge=' in url
        assert 'code_challenge_method=S256' in url
        assert 'transactions_r' in url
        # The verifier never leaves this machine
        assert credentials.oauth_verifier
        assert credentials.oauth_verifier not in url


def test_etsy_authorize_url_carries_the_state_nonce(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        url = A.oauth_begin(A.INTEGRATIONS['etsy'], credentials)
        assert credentials.oauth_state and credentials.oauth_state in url


def test_etsy_sends_the_real_callback_url(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        url = A.oauth_begin(A.INTEGRATIONS['etsy'], A.EtsyCredentials.query.one())
        assert 'etsy%2Fcallback' in url or 'etsy/callback' in url


def test_ebay_uses_the_sandbox_host_when_flagged(A, ebay):
    with A.app.test_request_context('/', base_url=BASE_URL):
        url = A.oauth_begin(A.INTEGRATIONS['ebay'], A.EbayCredentials.query.one())
        assert url.startswith('https://auth.sandbox.ebay.com/oauth2/authorize')


def test_ebay_uses_the_production_host_by_default(A, ebay):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EbayCredentials.query.one()
        credentials.sandbox = False
        A.db.session.commit()
        url = A.oauth_begin(A.INTEGRATIONS['ebay'], credentials)
        assert url.startswith('https://auth.ebay.com/oauth2/authorize')


def test_ebay_sends_its_runame_where_etsy_sends_a_url(A, ebay):
    """eBay's RuName is an *alias* for the redirect URI, sent in its place."""
    with A.app.test_request_context('/', base_url=BASE_URL):
        url = A.oauth_begin(A.INTEGRATIONS['ebay'], A.EbayCredentials.query.one())
        assert 'redirect_uri=My-RuName' in url
        assert 'code_challenge' not in url     # eBay does not use PKCE


def test_connecting_without_a_client_id_is_refused(A, ctx):
    credentials = A.EtsyCredentials(client_id='', client_secret='')
    A.db.session.add(credentials)
    A.db.session.commit()
    with A.app.test_request_context('/', base_url=BASE_URL):
        with pytest.raises(A.IntegrationError, match='client ID'):
            A.oauth_begin(A.INTEGRATIONS['etsy'], credentials)


# --- Exchanging the code ----------------------------------------------------

def test_etsy_exchange_sends_the_verifier_in_the_body(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        A.oauth_begin(A.INTEGRATIONS['etsy'], credentials)
        state = credentials.oauth_state

        with mock.patch.object(A.requests, 'request', return_value=token_response(
                {'access_token': 'ETSY_AT', 'refresh_token': 'ETSY_RT',
                 'expires_in': 3600})) as request:
            A.oauth_complete(A.INTEGRATIONS['etsy'], credentials, 'THE_CODE',
                             state=state)

        sent = request.call_args.kwargs['data']
        assert 'code_verifier' in sent
        assert sent['client_id'] == 'ETSYKEY'
        assert sent['grant_type'] == 'authorization_code'

        assert credentials.access_token == 'ETSY_AT'
        assert credentials.refresh_token == 'ETSY_RT'
        # The nonce and verifier are single-use
        assert credentials.oauth_state == '' and credentials.oauth_verifier == ''


def test_ebay_exchange_uses_http_basic_auth(A, ebay):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EbayCredentials.query.one()
        with mock.patch.object(A.requests, 'request', return_value=token_response(
                {'access_token': 'EBAY_AT', 'refresh_token': 'EBAY_RT',
                 'expires_in': 7200,
                 'refresh_token_expires_in': 47304000})) as request:
            A.oauth_complete(A.INTEGRATIONS['ebay'], credentials, 'CODE')

        headers = request.call_args.kwargs['headers']
        assert headers['Authorization'].startswith('Basic ')
        assert 'client_secret' not in request.call_args.kwargs['data']
        # eBay's refresh token expires too, so an aged-out connection can say
        # "reconnect" rather than failing obscurely
        assert credentials.refresh_token_expires_at is not None


def test_a_replayed_state_is_rejected(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        credentials.oauth_state = 'expected'
        with pytest.raises(A.IntegrationError, match='unexpected state'):
            A.oauth_complete(A.INTEGRATIONS['etsy'], credentials, 'CODE',
                             state='attacker-supplied')


def test_an_empty_stored_state_is_rejected(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        credentials.oauth_state = ''
        with pytest.raises(A.IntegrationError):
            A.oauth_complete(A.INTEGRATIONS['etsy'], credentials, 'CODE', state='')


def test_a_token_response_with_no_token_is_an_error(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        with mock.patch.object(A.requests, 'request', return_value=token_response(
                {'error': 'invalid_grant',
                 'error_description': 'code already used'})):
            with pytest.raises(A.IntegrationError, match='code already used'):
                A.oauth_complete(A.INTEGRATIONS['etsy'], credentials, 'CODE')


# --- Using and renewing the token ------------------------------------------

def test_a_valid_token_is_reused_without_a_network_call(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        credentials.access_token = 'CACHED'
        credentials.refresh_token = 'RT'
        credentials.access_token_expires_at = A.datetime.now() + A.timedelta(hours=1)
        A.db.session.commit()

        with mock.patch.object(A.requests, 'request',
                               side_effect=AssertionError('must not call out')):
            assert A.oauth_access_token(A.INTEGRATIONS['etsy'], credentials) == 'CACHED'


def test_an_expired_token_is_refreshed(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        credentials.access_token = 'STALE'
        credentials.refresh_token = 'RT'
        credentials.access_token_expires_at = A.datetime.now() - A.timedelta(minutes=1)
        A.db.session.commit()

        with mock.patch.object(A.requests, 'request', return_value=token_response(
                {'access_token': 'REFRESHED', 'expires_in': 3600})) as request:
            assert A.oauth_access_token(A.INTEGRATIONS['etsy'],
                                        credentials) == 'REFRESHED'
        assert request.call_args.kwargs['data']['grant_type'] == 'refresh_token'


def test_a_token_inside_the_safety_margin_is_renewed_early(A, etsy):
    """So it cannot expire mid-import."""
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        credentials.access_token = 'ABOUT-TO-LAPSE'
        credentials.refresh_token = 'RT'
        credentials.access_token_expires_at = A.datetime.now() + A.timedelta(minutes=1)
        A.db.session.commit()

        with mock.patch.object(A.requests, 'request', return_value=token_response(
                {'access_token': 'RENEWED', 'expires_in': 3600})):
            assert A.oauth_access_token(A.INTEGRATIONS['etsy'],
                                        credentials) == 'RENEWED'


def test_ebay_restates_the_scopes_when_refreshing(A, ebay):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EbayCredentials.query.one()
        credentials.refresh_token = 'RT'
        A.db.session.commit()

        with mock.patch.object(A.requests, 'request', return_value=token_response(
                {'access_token': 'AT', 'expires_in': 7200})) as request:
            A.oauth_access_token(A.INTEGRATIONS['ebay'], credentials)
        assert 'scope' in request.call_args.kwargs['data']


def test_an_unconnected_platform_says_so(A, etsy):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EtsyCredentials.query.one()
        with pytest.raises(A.IntegrationError, match='not connected'):
            A.oauth_access_token(A.INTEGRATIONS['etsy'], credentials)


def test_an_expired_refresh_token_asks_for_a_reconnect(A, ebay):
    with A.app.test_request_context('/', base_url=BASE_URL):
        credentials = A.EbayCredentials.query.one()
        credentials.refresh_token = 'RT'
        credentials.refresh_token_expires_at = A.datetime.now() - A.timedelta(days=1)
        A.db.session.commit()

        with pytest.raises(A.IntegrationError, match='reconnect'):
            A.oauth_access_token(A.INTEGRATIONS['ebay'], credentials)


# --- Routes -----------------------------------------------------------------

def test_connect_is_only_offered_for_oauth_platforms(client):
    assert client.post('/integrations/shopify/connect').status_code == 404
    assert client.post('/integrations/nope/connect').status_code == 404


def test_connect_redirects_to_the_marketplace(A, client, etsy):
    response = client.post('/integrations/etsy/connect')
    assert response.status_code == 302
    assert response.headers['Location'].startswith('https://www.etsy.com/oauth/connect')


def test_connect_saves_what_was_typed_first(A, client):
    """The button lives inside the Management form, so a client ID pasted a
    moment ago must be saved before the operator is sent off."""
    response = client.post('/integrations/etsy/connect', data={
        'name': 'Test Co', 'etsy_enabled': 'on', 'etsy_client_id': 'JUST-TYPED',
        'etsy_client_secret': 'JUST-TYPED-SECRET'})
    assert response.status_code == 302
    assert 'client_id=JUST-TYPED' in response.headers['Location']
    with A.app.app_context():
        assert A.EtsyCredentials.query.one().client_id == 'JUST-TYPED'


def test_the_callback_completes_the_exchange(A, client, etsy):
    connect = client.post('/integrations/etsy/connect')
    with A.app.app_context():
        state = A.EtsyCredentials.query.one().oauth_state

    with mock.patch.object(A.requests, 'request', return_value=token_response(
            {'access_token': 'AT', 'refresh_token': 'RT', 'expires_in': 3600})):
        response = client.get(f'/etsy/callback?code=THE_CODE&state={state}')

    assert response.status_code == 302
    with A.app.app_context():
        assert A.EtsyCredentials.query.one().refresh_token == 'RT'


def test_the_callback_reports_a_declined_connection(A, client, etsy):
    response = client.get('/etsy/callback?error=access_denied',
                          follow_redirects=True)
    assert b'declined the connection' in response.data


def test_the_callback_requires_login(anon_client):
    """A stray hit from anyone not signed in must not enter the token exchange."""
    assert anon_client.get('/etsy/callback?code=x').status_code == 302


def test_the_paste_fallback_accepts_a_bare_code(A, client, etsy):
    with mock.patch.object(A.requests, 'request', return_value=token_response(
            {'access_token': 'AT', 'refresh_token': 'RT', 'expires_in': 3600})):
        response = client.post('/integrations/etsy/paste_code',
                               data={'code': 'PASTED'}, follow_redirects=True)
    assert response.status_code == 200
    with A.app.app_context():
        assert A.EtsyCredentials.query.one().refresh_token == 'RT'


def test_the_paste_fallback_accepts_a_whole_redirected_url(A, client, etsy):
    url = 'http://192.168.1.194:4444/etsy/callback?code=FROM-URL&state=abc'
    with mock.patch.object(A.requests, 'request', return_value=token_response(
            {'access_token': 'AT', 'refresh_token': 'RT',
             'expires_in': 3600})) as request:
        client.post('/integrations/etsy/paste_code', data={'code': url})
    assert request.call_args.kwargs['data']['code'] == 'FROM-URL'


def test_pasting_nothing_is_reported(A, client, etsy):
    response = client.post('/integrations/etsy/paste_code', data={'code': ''},
                           follow_redirects=True)
    assert b'Paste the authorization code' in response.data


def test_disconnect_forgets_every_token(A, client, etsy):
    with A.app.app_context():
        credentials = A.EtsyCredentials.query.one()
        credentials.access_token, credentials.refresh_token = 'AT', 'RT'
        credentials.access_token_expires_at = A.datetime.now()
        A.db.session.commit()

    assert client.post('/integrations/etsy/disconnect').status_code == 302
    with A.app.app_context():
        credentials = A.EtsyCredentials.query.one()
        assert credentials.access_token == '' and credentials.refresh_token == ''
        assert credentials.access_token_expires_at is None


def test_oauth_status_never_exposes_a_token(A, client, etsy):
    with A.app.app_context():
        credentials = A.EtsyCredentials.query.one()
        credentials.refresh_token = 'ZZ-REFRESH-ZZ'
        credentials.access_token = 'ZZ-ACCESS-ZZ'
        A.db.session.commit()

    with A.app.test_request_context('/', base_url=BASE_URL):
        status = A.oauth_status(A.INTEGRATIONS['etsy'])
    assert status['connected'] is True
    assert 'ZZ-REFRESH-ZZ' not in repr(status)
    assert 'ZZ-ACCESS-ZZ' not in repr(status)
