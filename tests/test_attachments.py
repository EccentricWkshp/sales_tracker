"""Product attachments — datasheets shipped with a receipt (roadmap F1).

The bytes live under instance/product_attachments/ rather than static/, so they
are only reachable through a login-required route. ``conftest`` redirects
``PRODUCT_ATTACHMENT_DIR`` at a per-test temp directory.
"""
import io
import os

import pytest

PDF_BYTES = b'%PDF-1.4\n% fake datasheet\n'


@pytest.fixture
def upload(client):
    def _upload(product_id, *files):
        return client.post(
            f'/products/{product_id}/attachments',
            content_type='multipart/form-data',
            data={'files': [(io.BytesIO(body), name) for body, name in files]})
    return _upload


def test_upload_accepts_several_files(upload, widget_id):
    response = upload(widget_id,
                      (PDF_BYTES, 'Widget Datasheet.pdf'),
                      (b'hello', 'notes.txt'))
    assert response.status_code == 200, response.data
    body = response.get_json()
    assert body['success'] is True
    assert len(body['attachments']) == 2
    assert body['attachments'][0]['size_label']
    assert '/products/attachments/' in body['attachments'][0]['url']


def test_stored_name_is_generated_not_the_upload_name(A, upload, widget_id):
    """An operator's filename must never decide a path."""
    upload(widget_id, (PDF_BYTES, 'Widget Datasheet.pdf'))
    with A.app.app_context():
        attachment = A.ProductAttachment.query.filter_by(product_id=widget_id).one()
        assert attachment.stored_name != attachment.original_name
        assert attachment.stored_name.endswith('.pdf')
        assert ' ' not in attachment.stored_name
        assert attachment.original_name.endswith('.pdf')


def test_a_traversal_filename_cannot_escape_the_directory(A, upload, widget_id):
    upload(widget_id, (PDF_BYTES, '../../evil.pdf'))
    with A.app.app_context():
        stored = A.ProductAttachment.query.filter_by(product_id=widget_id).one()
        assert '..' not in stored.stored_name
        assert os.sep not in stored.stored_name and '/' not in stored.stored_name
        assert os.path.exists(os.path.join(A.PRODUCT_ATTACHMENT_DIR,
                                           stored.stored_name))


def test_bytes_land_on_disk(A, upload, widget_id):
    upload(widget_id, (PDF_BYTES, 'sheet.pdf'))
    with A.app.app_context():
        attachment = A.ProductAttachment.query.filter_by(product_id=widget_id).one()
        path = os.path.join(A.PRODUCT_ATTACHMENT_DIR, attachment.stored_name)
        assert os.path.exists(path)
        assert attachment.size_bytes == len(PDF_BYTES)


def test_print_flag_defaults_on(A, upload, widget_id):
    upload(widget_id, (PDF_BYTES, 'sheet.pdf'))
    with A.app.app_context():
        assert A.ProductAttachment.query.filter_by(product_id=widget_id).one() \
            .print_with_receipt is True


@pytest.mark.parametrize('filename', ['trojan.exe', 'script.bat', 'lib.so',
                                      'noextension'])
def test_disallowed_extensions_are_rejected(A, upload, widget_id, filename):
    response = upload(widget_id, (b'MZ', filename))
    assert response.status_code == 400
    assert response.get_json()['success'] is False
    with A.app.app_context():
        assert A.ProductAttachment.query.count() == 0


def test_a_mixed_batch_saves_the_allowed_files_and_reports_the_rest(upload,
                                                                    widget_id):
    response = upload(widget_id, (PDF_BYTES, 'good.pdf'), (b'MZ', 'bad.exe'))
    assert response.status_code == 200
    body = response.get_json()
    assert len(body['attachments']) == 1
    assert body['rejected'] and 'bad.exe' in body['rejected'][0]


def test_uploading_nothing_is_a_400(client, widget_id):
    response = client.post(f'/products/{widget_id}/attachments',
                           content_type='multipart/form-data', data={})
    assert response.status_code == 400


def test_upload_to_a_missing_product_404s(upload):
    assert upload(99999, (PDF_BYTES, 'sheet.pdf')).status_code == 404


def test_download_serves_the_bytes(A, client, upload, widget_id):
    upload(widget_id, (PDF_BYTES, 'sheet.pdf'))
    with A.app.app_context():
        attachment_id = A.ProductAttachment.query.one().id

    response = client.get(f'/products/attachments/{attachment_id}')
    assert response.status_code == 200
    assert response.data == PDF_BYTES


def test_download_requires_login(A, anon_client, client, upload, widget_id):
    """The whole reason the bytes are not in static/."""
    upload(widget_id, (PDF_BYTES, 'sheet.pdf'))
    with A.app.app_context():
        attachment_id = A.ProductAttachment.query.one().id
    assert anon_client.get(f'/products/attachments/{attachment_id}').status_code == 302


def test_print_flag_can_be_turned_off(A, client, upload, widget_id):
    upload(widget_id, (PDF_BYTES, 'sheet.pdf'))
    with A.app.app_context():
        attachment_id = A.ProductAttachment.query.one().id

    response = client.post(f'/products/attachments/{attachment_id}/print_flag',
                           json={'print_with_receipt': False})
    assert response.status_code == 200
    assert response.get_json()['print_with_receipt'] is False
    with A.app.app_context():
        assert A.db.session.get(A.ProductAttachment,
                                attachment_id).print_with_receipt is False


def test_delete_removes_the_row_and_the_file(A, client, upload, widget_id):
    upload(widget_id, (PDF_BYTES, 'sheet.pdf'))
    with A.app.app_context():
        attachment = A.ProductAttachment.query.one()
        attachment_id = attachment.id
        path = os.path.join(A.PRODUCT_ATTACHMENT_DIR, attachment.stored_name)

    assert client.post(f'/products/attachments/{attachment_id}/delete').status_code == 200
    assert not os.path.exists(path)
    with A.app.app_context():
        assert A.db.session.get(A.ProductAttachment, attachment_id) is None


def test_deleting_a_product_cascades_to_its_attachments(A, client, upload):
    product_id = client.post('/products/add', json={
        'sku': 'CASCADE-1', 'description': 'Doomed', 'price': '1'}).get_json()['id']
    upload(product_id, (PDF_BYTES, 'sheet.pdf'))

    assert client.post(f'/products/delete/{product_id}').status_code == 200
    with A.app.app_context():
        assert A.ProductAttachment.query.filter_by(product_id=product_id).count() == 0


# --- The receipt print page -------------------------------------------------

def test_datasheets_appear_on_the_print_page(A, client, upload, customer_id,
                                             widget_id, make_sale):
    upload(widget_id, (PDF_BYTES, 'sheet.pdf'))
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])

    body = client.get(f'/sales/print/{sale_id}').get_data(as_text=True)
    assert 'datasheet' in body.lower()
    assert body.count('class="datasheet-link"') == 1
    # The bar is for the screen; it must not print with the receipt
    assert 'no-print' in body


def test_a_repeated_product_prints_one_datasheet(A, client, upload, customer_id,
                                                 widget_id, make_sale):
    """Two line items of the same product must not offer the sheet twice."""
    upload(widget_id, (PDF_BYTES, 'sheet.pdf'))
    sale_id = make_sale(customer_id, [(widget_id, 1, 100), (widget_id, 2, 100)])

    body = client.get(f'/sales/print/{sale_id}').get_data(as_text=True)
    assert body.count('class="datasheet-link"') == 1
    with A.app.app_context():
        sale = A.db.session.get(A.SalesReceipt, sale_id)
        assert len(A.receipt_datasheets(sale)) == 1


def test_two_products_sharing_a_datasheet_offer_it_once(A, client, upload,
                                                        customer_id, widget_id,
                                                        gadget_id, make_sale):
    upload(widget_id, (PDF_BYTES, 'shared.pdf'))
    with A.app.app_context():
        attachment = A.ProductAttachment.query.one()
        # A second product pointing at the same stored file
        A.db.session.add(A.ProductAttachment(
            product_id=gadget_id, stored_name=attachment.stored_name,
            original_name=attachment.original_name))
        A.db.session.commit()

    sale_id = make_sale(customer_id, [(widget_id, 1, 100), (gadget_id, 1, 10)])
    body = client.get(f'/sales/print/{sale_id}').get_data(as_text=True)
    # Two distinct attachment rows, but only one file — one link per row is
    # correct here; what must not happen is the same row appearing twice
    with A.app.app_context():
        sale = A.db.session.get(A.SalesReceipt, sale_id)
        sheets = A.receipt_datasheets(sale)
        assert len({sheet['attachment'].id for sheet in sheets}) == len(sheets)
    assert 'datasheet' in body.lower()


def test_a_flag_off_attachment_is_left_off_the_print_page(A, client, upload,
                                                          customer_id, widget_id,
                                                          make_sale):
    upload(widget_id, (PDF_BYTES, 'sheet.pdf'), (b'internal', 'internal.txt'))
    with A.app.app_context():
        hidden = A.ProductAttachment.query.filter_by(
            original_name='internal.txt').one()
        hidden.print_with_receipt = False
        A.db.session.commit()

    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    body = client.get(f'/sales/print/{sale_id}').get_data(as_text=True)
    assert 'internal.txt' not in body
    assert body.count('class="datasheet-link"') == 1


def test_a_sale_with_no_datasheets_has_no_bar(client, customer_id, widget_id,
                                              make_sale):
    sale_id = make_sale(customer_id, [(widget_id, 1, 100)])
    body = client.get(f'/sales/print/{sale_id}').get_data(as_text=True)
    assert 'class="datasheet-link"' not in body


def test_human_size_labels(A):
    assert A.human_size(0) == '0 B'
    assert A.human_size(512) == '512 B'
    assert A.human_size(2048) == '2.0 KB'
    assert A.human_size(5 * 1024 * 1024) == '5.0 MB'
