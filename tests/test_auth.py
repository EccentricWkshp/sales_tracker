"""Login, logout and the gating that keeps the app off the open LAN."""
import pytest

from conftest import TEST_PASSWORD, TEST_USERNAME


def test_good_password_redirects_to_the_dashboard(anon_client):
    response = anon_client.post('/login', data={
        'username': TEST_USERNAME, 'password': TEST_PASSWORD})
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')


def test_bad_password_does_not_authenticate(anon_client):
    response = anon_client.post(
        '/login', data={'username': TEST_USERNAME, 'password': 'wrong'},
        follow_redirects=True)
    assert b'Invalid username or password' in response.data
    # Still anonymous: the dashboard must bounce back to the login page
    assert anon_client.get('/').status_code == 302


def test_unknown_user_does_not_authenticate(anon_client):
    response = anon_client.post(
        '/login', data={'username': 'nobody', 'password': TEST_PASSWORD},
        follow_redirects=True)
    assert b'Invalid username or password' in response.data


def test_login_tolerates_a_missing_field(anon_client):
    """The route used to index request.form directly and 400 on a bare post."""
    response = anon_client.post('/login', data={}, follow_redirects=True)
    assert response.status_code == 200


def test_next_only_follows_same_origin_paths(anon_client):
    response = anon_client.post(
        '/login?next=https://evil.example.com/steal',
        data={'username': TEST_USERNAME, 'password': TEST_PASSWORD})
    assert 'evil.example.com' not in response.headers.get('Location', '')


@pytest.mark.parametrize('hostile', [
    '//evil.example.com/steal',      # protocol-relative
    'https://evil.example.com',
    'javascript:alert(1)',
])
def test_next_rejects_hostile_targets(anon_client, hostile):
    response = anon_client.post(f'/login?next={hostile}', data={
        'username': TEST_USERNAME, 'password': TEST_PASSWORD})
    location = response.headers.get('Location', '')
    assert 'evil.example.com' not in location and 'javascript' not in location


def test_next_follows_a_local_path(anon_client):
    response = anon_client.post('/login?next=/sales', data={
        'username': TEST_USERNAME, 'password': TEST_PASSWORD})
    assert response.headers['Location'].endswith('/sales')


def test_logout_ends_the_session(client):
    assert client.get('/').status_code == 200
    client.get('/logout')
    assert client.get('/').status_code == 302


@pytest.mark.parametrize('path', [
    '/', '/sales', '/customers', '/products', '/management', '/state_taxes',
    '/finance', '/finance/banking', '/sales/pending',
    '/api/sales', '/api/customers', '/api/products', '/api/transactions',
    '/api/pending_orders',
])
def test_pages_require_login(anon_client, path):
    response = anon_client.get(path)
    assert response.status_code == 302
    assert '/login' in response.headers['Location']


@pytest.mark.parametrize('path', [
    '/sales/add', '/customers/add', '/products/add', '/customers/merge',
])
def test_write_routes_require_login(anon_client, path):
    assert anon_client.post(path, json={}).status_code == 302
