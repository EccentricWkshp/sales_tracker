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

    dismissFlashAfter(flashContainer);
}

/* Every banner goes stale and clears itself after 30 seconds, whatever its
 * category — long enough to read a list of failed orders, short enough that a
 * stale message never sits over the page. Dismissing early still works. */
var FLASH_TIMEOUT_MS = 60000;

function dismissFlashAfter(flashContainer, delay) {
    setTimeout(function () {
        flashContainer.style.transition = 'opacity 0.4s ease-out';
        flashContainer.style.opacity = '0';
        setTimeout(function () {
            flashContainer.remove();
        }, 400);
    }, delay || FLASH_TIMEOUT_MS);
}

/* Server-rendered flashes (base.html) are in the DOM before this runs, so they
 * need the same treatment as the ones showFlashMessage creates. */
document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.flash-messages').forEach(function (container) {
        dismissFlashAfter(container);
    });
});

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
