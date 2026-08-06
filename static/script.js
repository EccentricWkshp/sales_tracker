/* static/script.js — shared helpers, loaded on every page via base.html */

/* Show a dismissible banner at the top of the page.
 * category is one of: success | error | warning | info
 * details is an optional array of strings rendered as a bullet list, used by the
 * order importers to show which individual orders failed. */
function showFlashMessage(message, category, details) {
    var existingFlash = document.querySelector('.flash-messages');
    if (existingFlash) {
        existingFlash.remove();
    }

    var flashContainer = document.createElement('ul');
    flashContainer.className = 'flash-messages';

    var flashItem = document.createElement('li');
    flashItem.className = 'flash-message flash-' + (category || 'info');
    flashItem.textContent = message;

    if (details && details.length) {
        var list = document.createElement('ul');
        details.slice(0, 10).forEach(function (detail) {
            var entry = document.createElement('li');
            entry.textContent = detail;
            list.appendChild(entry);
        });
        if (details.length > 10) {
            var more = document.createElement('li');
            more.textContent = '…and ' + (details.length - 10) + ' more (see logs/sales_tracker.log)';
            list.appendChild(more);
        }
        flashItem.appendChild(list);
    }

    var closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'flash-close';
    closeBtn.innerHTML = '&times;';
    closeBtn.onclick = function () {
        flashContainer.remove();
    };

    flashItem.appendChild(closeBtn);
    flashContainer.appendChild(flashItem);
    document.body.insertBefore(flashContainer, document.body.firstChild);

    dismissFlashAfter(flashContainer,
                      flashTimeoutFor(category, !!(details && details.length)));
}

/* How long a banner sits before fading itself out. Dismissing early still works.
 *
 * The banner is position:fixed across the top, over the header, so a stale one
 * is genuinely in the way — these are short. banking.html's showAlert() clears
 * after 5s and is the reference point.
 *
 * Tiered because the banners do not all carry the same weight:
 *   success/info   a confirmation of something the operator just did
 *   error/warning  something they may still need to act on
 *   with details   an import naming which individual orders failed, which takes
 *                  real time to read
 */
var FLASH_TIMEOUT_MS = 6000;
var FLASH_TIMEOUT_IMPORTANT_MS = 15000;
var FLASH_TIMEOUT_DETAILED_MS = 30000;

function flashTimeoutFor(category, hasDetails) {
    if (hasDetails) return FLASH_TIMEOUT_DETAILED_MS;
    if (category === 'error' || category === 'warning') return FLASH_TIMEOUT_IMPORTANT_MS;
    return FLASH_TIMEOUT_MS;
}

function dismissFlashAfter(flashContainer, delay) {
    setTimeout(function () {
        flashContainer.style.transition = 'opacity 0.4s ease-out';
        flashContainer.style.opacity = '0';
        setTimeout(function () {
            flashContainer.remove();
        }, 400);
    }, delay || FLASH_TIMEOUT_MS);
}

/* Server-rendered flashes (base.html, login.html) are already in the DOM, so
 * they need the same treatment as the ones showFlashMessage builds. The category
 * has to be read back off the class, since there is no JS call to carry it. */
function initServerFlashes() {
    document.querySelectorAll('.flash-messages').forEach(function (container) {
        var delay = FLASH_TIMEOUT_MS;
        container.querySelectorAll('.flash-message').forEach(function (item) {
            var category = item.classList.contains('flash-error') ? 'error'
                         : item.classList.contains('flash-warning') ? 'warning'
                         : 'info';
            // One container can hold several messages; the slowest one wins
            delay = Math.max(delay, flashTimeoutFor(category, !!item.querySelector('ul')));
        });
        dismissFlashAfter(container, delay);
    });
}

// login.html loads this at the end of its body, where DOMContentLoaded may
// already have fired — registering a listener then would never run.
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initServerFlashes);
} else {
    initServerFlashes();
}

/* Pull the most useful message out of a failed jQuery AJAX response. Routes
 * return either {error: ...} or {message: ...} depending on their age. */
function serverMessage(xhr, fallback) {
    var body = xhr && xhr.responseJSON;
    if (body) {
        if (body.error) return body.error;
        if (body.message) return body.message;
    }
    if (xhr && xhr.status === 0) return 'Lost connection to the server.';
    return fallback || 'Unexpected server error';
}

function refreshGrid(url, gridApi) {
    return fetch(url)
        .then(function (response) {
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return response.json();
        })
        .then(function (data) {
            gridApi.setGridOption('rowData', data);
        })
        .catch(function (error) {
            console.error('Error fetching data:', error);
            showFlashMessage('Could not refresh the list — reload the page to see current data.', 'error');
        });
}

function greaterlessComparator(filterValue, cellValue) {
    if (cellValue == null) return -1;
    if (filterValue == null) return 1;
    const cellValueNumber = parseFloat(cellValue);
    const filterValueNumber = parseFloat(filterValue);

    if (isNaN(cellValueNumber) || isNaN(filterValueNumber)) return -1;

    if (cellValueNumber > filterValueNumber) {
        return 1;
    } else if (cellValueNumber < filterValueNumber) {
        return -1;
    } else {
        return 0;
    }
}

function caseInsensitiveComparator(valueA, valueB) {
    if (valueA == null) return valueB == null ? 0 : -1;
    if (valueB == null) return 1;
    return valueA.toString().toLowerCase().localeCompare(valueB.toString().toLowerCase());
}

function dateComparator(date1, date2) {
    var dateParts1 = date1.split('-');
    var dateParts2 = date2.split('-');

    var d1 = new Date(dateParts1[2], dateParts1[0] - 1, dateParts1[1]);
    var d2 = new Date(dateParts2[2], dateParts2[0] - 1, dateParts2[1]);

    if (d1 < d2) return -1;
    if (d1 > d2) return 1;
    return 0;
}

/**
 * agDateColumnFilter comparator for the MM-DD-YYYY strings the API emits.
 *
 * Null-safe: an unshipped sale has shipdate null, and the per-grid copies of
 * this used to call .split() on it and throw, which silently killed the filter.
 */
function mmddyyyyFilterComparator(filterLocalDateAtMidnight, cellValue) {
    if (!cellValue) return -1;
    var parts = String(cellValue).split('-');
    if (parts.length !== 3) return -1;
    var cellDate = new Date(Number(parts[2]), Number(parts[0]) - 1, Number(parts[1]));
    if (cellDate < filterLocalDateAtMidnight) return -1;
    if (cellDate > filterLocalDateAtMidnight) return 1;
    return 0;
}

function getDateFilterRange() {
    var filterModel = gridApi.getFilterModel();
    if (filterModel && filterModel.date) {
        var model = filterModel.date;
        var fromDate = model.dateFrom ? new Date(model.dateFrom).toLocaleDateString('en-CA') : null;
        var toDate = model.dateTo ? new Date(model.dateTo).toLocaleDateString('en-CA') : fromDate;
        return { fromDate, toDate };
    }
    return null;
}

function currencyFormatter(params) {
    if (params.value === null || params.value === undefined || params.value === '') return '';
    var amount = typeof params.value === 'number' ? params.value : parseFloat(params.value);
    if (isNaN(amount)) return '';
    return amount.toLocaleString(undefined, {
        style: 'currency',
        currency: 'USD'
    });
}

function emailValueFormatter(params) {
    const email = params.value;
    if (email && email.includes("placeholder_")) {
      return ''; // Return empty string if it contains "placeholder_"
    }
    return email; // Otherwise return the email as is
}

function deleteSale(saleId, url, gridApi) {
    $.ajax({
        url: "/sales/delete/" + saleId,
        method: "POST",
        success: function (response) {
            refreshGrid(url, gridApi);
            showFlashMessage(response.message || 'Sale deleted.', 'success');
        },
        error: function (xhr) {
            showFlashMessage(serverMessage(xhr, 'Error deleting sale'), 'error');
        }
    });
}

/* Shared handler for the dashboard's order-fetch forms. The importers return
 * 207 with an errors[] array when some orders failed but the rest imported, so
 * a partial success must not be reported as a plain success. */
function submitFetchForm(form, url, resultSelector, onDone) {
    var $button = $(form).find('button[type="submit"]');
    var original = $button.html();
    $button.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Fetching…');

    $.ajax({
        url: url,
        method: 'POST',
        data: $(form).serialize(),
        success: function (response, status, xhr) {
            var errors = response.errors || [];
            var category = errors.length ? 'warning' : 'success';
            $(resultSelector).html(
                '<div class="alert alert-' + (errors.length ? 'warning' : 'success') + '">' +
                $('<div>').text(response.message).html() + '</div>');
            showFlashMessage(response.message, category, errors);
            if (onDone) onDone();
        },
        error: function (xhr) {
            var message = serverMessage(xhr, 'Could not fetch orders');
            $(resultSelector).html('<div class="alert alert-danger">' +
                $('<div>').text(message).html() + '</div>');
            showFlashMessage(message, 'error');
        },
        complete: function () {
            $button.prop('disabled', false).html(original);
        }
    });
}
