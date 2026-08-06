"""Flash banners clear themselves.

They are `position: fixed` across the top of the page, over the header, so one
that lingers is genuinely in the way. banking.html's `showAlert()` clears after
5s and is the reference point; `script.js` tiers the flash timeouts around it.

The dismissal itself is JavaScript and is not exercised here — what these tests
protect is the wiring that made it not run at all, and the constants, which had
drifted to 60s while the comment beside them said 30.
"""
import re

import pytest

from conftest import TEST_PASSWORD, TEST_USERNAME


def _static(name):
    from conftest import PROJECT_ROOT
    return (PROJECT_ROOT / 'static' / name).read_text(encoding='utf-8')


def _template(name):
    from conftest import PROJECT_ROOT
    return (PROJECT_ROOT / 'templates' / name).read_text(encoding='utf-8')


def _constant(name):
    match = re.search(rf'var {name}\s*=\s*(\d+)\s*;', _static('script.js'))
    assert match, f'{name} is not defined in script.js'
    return int(match.group(1))


# --- The constants ----------------------------------------------------------

TIERS = ['FLASH_TIMEOUT_MS', 'FLASH_TIMEOUT_IMPORTANT_MS', 'FLASH_TIMEOUT_DETAILED_MS']


@pytest.mark.parametrize('name', TIERS)
def test_each_tier_is_defined(name):
    assert _constant(name) > 0


def test_the_tiers_are_ordered():
    assert (_constant('FLASH_TIMEOUT_MS')
            < _constant('FLASH_TIMEOUT_IMPORTANT_MS')
            < _constant('FLASH_TIMEOUT_DETAILED_MS'))


def test_an_ordinary_banner_clears_promptly():
    """Long enough to read a sentence, short enough not to sit over the header."""
    assert 3000 <= _constant('FLASH_TIMEOUT_MS') <= 10000


def test_an_error_lingers_but_not_indefinitely():
    assert 10000 <= _constant('FLASH_TIMEOUT_IMPORTANT_MS') <= 20000


def test_a_detailed_banner_can_be_read_through():
    """An import failure lists up to ten order numbers."""
    assert 20000 <= _constant('FLASH_TIMEOUT_DETAILED_MS') <= 45000


# --- The wiring -------------------------------------------------------------

def test_the_dismissal_runs_even_if_the_dom_is_already_parsed():
    """login.html loads script.js at the end of its body, where DOMContentLoaded
    may already have fired — registering a listener then would never run."""
    body = _static('script.js')
    assert "document.readyState === 'loading'" in body
    assert 'initServerFlashes' in body


def test_showflashmessage_passes_a_tier():
    """It used to take the single flat default regardless of severity."""
    assert re.search(r'dismissFlashAfter\(\s*flashContainer,\s*\n?\s*flashTimeoutFor\(',
                     _static('script.js'))


@pytest.mark.parametrize('template', ['base.html', 'login.html'])
def test_pages_that_render_flashes_load_script_js(template):
    """login.html does not extend base.html, so it has to ask for script.js
    itself. Without it "Invalid username or password" sat over the header until
    it was clicked away."""
    body = _template(template)
    assert 'get_flashed_messages' in body, f'{template} renders no flashes'
    assert "filename='script.js'" in body, \
        f'{template} renders flashes but never loads script.js to time them out'


@pytest.mark.parametrize('category', ['error', 'warning', 'success', 'info'])
def test_the_category_survives_into_the_class(A, category):
    """initServerFlashes reads the tier back off the class, since a server-side
    flash has no JS call to carry it."""
    with A.app.test_request_context('/'):
        A.flash('a message', category)
        rendered = A.render_template('base.html')
    assert f'flash-{category}' in rendered


# --- End to end through real responses --------------------------------------

def test_a_login_failure_renders_a_dismissible_banner(anon_client):
    response = anon_client.post('/login', data={'username': TEST_USERNAME,
                                                'password': 'wrong'},
                                follow_redirects=True)
    body = response.get_data(as_text=True)
    assert 'flash-error' in body
    assert 'flash-close' in body            # manual dismissal still offered
    assert 'script.js' in body              # ...and automatic dismissal is wired


def test_a_successful_login_banner_is_also_timed(anon_client):
    response = anon_client.post('/login', data={'username': TEST_USERNAME,
                                                'password': TEST_PASSWORD},
                                follow_redirects=True)
    body = response.get_data(as_text=True)
    assert 'flash-success' in body
    assert 'script.js' in body


def test_a_flashed_page_carries_the_container_the_script_looks_for(client):
    """The selector in initServerFlashes is '.flash-messages'."""
    response = client.post('/management', data={'name': 'Test Co'},
                           follow_redirects=True)
    assert 'class="flash-messages"' in response.get_data(as_text=True)
