function refreshGrid(url, gridApi) {
    fetch(url)
        .then(response => response.json())
        .then(data => {
            gridApi.setGridOption("rowData", data);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
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
    var filterModel = gridOptions.api.getFilterModel();
    if (filterModel && filterModel.date) {
        var model = filterModel.date;
        var fromDate = model.dateFrom ? new Date(model.dateFrom).toLocaleDateString('en-CA') : null;
        var toDate = model.dateTo ? new Date(model.dateTo).toLocaleDateString('en-CA') : fromDate;
        return { fromDate, toDate };
    }
    return null;
}

function currencyFormatter(params) {
    if (params.value === null || params.value === undefined) return '';
    return '$' + params.value.toFixed(2);
}

function deleteSale(saleId, url, gridApi) {
    $.ajax({
        url: "/sales/delete/" + saleId,
        method: "POST",
        success: function(response) {
            if (response.success) {
                //location.reload();
                refreshGrid(url, gridApi);
            } else {
                alert("Error deleting sale");
            }
        }
    });
}
