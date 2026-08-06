# Tests

The formalised version of the ad-hoc verification battery that was run by hand
through Phases A–F. Roadmap item **E6**.

```bat
venv\Scripts\python -m pip install -r requirements.txt -r requirements-dev.txt
venv\Scripts\python -m pytest
```

Around 478 checks, roughly a minute. Useful flags:

```bat
venv\Scripts\python -m pytest tests\test_import_pipeline.py   :: one module
venv\Scripts\python -m pytest -k adopted                      :: by name
venv\Scripts\python -m pytest -x -vv                          :: stop at the first failure
venv\Scripts\python -m pytest --cov=app --cov-report=html     :: coverage to htmlcov\
```

## Two safety rails, both in `conftest.py`

Read these before adding anything that touches configuration.

**The suite never opens the live database.** `app.py` builds the Flask app and
the SQLAlchemy engine at import time, so `SALES_TRACKER_DATABASE_URI` is set to a
throwaway file *before* `import app` — assigning `app.config` afterwards does not
rebind the engine. `conftest` then asserts the bound path really is the scratch
file and refuses to run if it is not. Each test gets the schema rebuilt from the
models and reseeded, so tests cannot leak state into each other.

**The suite never reaches a real integration.** The `.env` in this repo holds
live Shopify and Etsy credentials and `app.py` loads it on import; an early
ad-hoc run of this battery inherited them and made a real Shopify API call.
Every variable the registry reads is therefore blanked before import (which
`load_dotenv(override=False)` respects, since it skips keys already present) and
removed after it, driven by `INTEGRATIONS` so a newly registered variable cannot
slip past. `test_config.py` asserts the result, and a fresh database has every
integration disabled, so a fetch route refuses before attempting any call.

Outbound HTTP is mocked everywhere it appears — `requests.request` for the OAuth
token endpoints, `integration_request` for Shopify's token exchange. No test
makes a network call.

## Layout

| Module | Covers |
| --- | --- |
| `conftest.py` | DB binding, credential scrubbing, seeding, factories |
| `test_config.py` | The rails above, SQLite pragmas, session/cookie hardening |
| `test_auth.py` | Login, `?next=` open-redirect refusal, route gating |
| `test_pages.py` | Every page and JSON endpoint renders |
| `test_customers.py` | A4 merge, A6 escaping, A7 validation, placeholder emails |
| `test_sales.py` | D3 add/edit parity, server-computed total, A1, A2 |
| `test_products.py` | F2 fields, margin, validation |
| `test_attachments.py` | F1 upload/download/print flag/de-duplication/cascade |
| `test_money.py` | E4 Numeric columns, exactness, the JSON boundary, the migration |
| `test_grids.py` | D1 API-loaded grids and field bindings, D2 feedback rules |
| `test_flash.py` | Flash banners auto-dismiss, and the pages rendering them load script.js |
| `test_import_pipeline.py` | C1/C2/C4, adoption, receipt numbers, pending queue |
| `test_shopify.py` | Webhook HMAC and shop pinning, both auth routes, caching |
| `test_integrations.py` | E7/E8 registry, Management form, dashboard cards |
| `test_oauth.py` | PKCE, state nonce, refresh, paste-code fallback |
| `test_marketplaces.py` | Etsy and eBay field mapping |
| `test_state_taxes.py` | `get_state_info`'s output contract, report totals |
| `test_backup.py` | B1 snapshots and retention |

## Conventions

`A` is the imported `app` module — the naming the ad-hoc scripts used. Fixtures
return **ids**, not model instances, because each test crosses several app
contexts and a detached instance would raise.

The seed is one operator (`test-operator`, id 1), company details, one customer
and three products: `WIDGET-1` ($100, manufactured), `GADGET-1` (not
manufactured) and `OLD-1` (archived). `make_sale`, `make_customer` and
`processed_order` build anything beyond that.

`processed_order` produces the pipeline's *internal* order shape — what every
`process_*` function emits. Behaviour that must hold regardless of platform is
tested through it; per-platform field mapping belongs in `test_marketplaces.py`
or `test_shopify.py`.

**Money assertions on model attributes use exact `Decimal`, never
`pytest.approx`.** Since E4 those columns return `Decimal`, and the point of the
change is that a stored figure matches to the cent — `approx` would hide the
rounding regression the type exists to prevent. It also does not work here:
`approx` short-circuits on exact equality and otherwise tries
`float - Decimal`, which raises `TypeError` instead of failing readably. Values
read back out of a JSON response are still floats, so `approx` is right there.

## Known gaps recorded here

`test_import_pipeline.py` carries one `xfail(strict=True)`: an order parked in
the pending queue while the store withheld the buyer, then re-imported once the
details are available, creates the receipt but leaves the parked row behind —
`discard_pending_order` only runs when a receipt *already* existed. Completing
that stale row would write a second sale. Because the mark is strict, fixing the
gap turns the run red until the mark is removed, so it cannot be fixed and
forgotten.
