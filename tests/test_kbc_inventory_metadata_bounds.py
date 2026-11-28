"""Small authored metadata controls for the SQLite/Python admission boundary."""
from __future__ import annotations

import pytest
from kbc_k1_support import NOW, no_sockets  # noqa: F401
from test_kbc_inventory_store import CONTEXT, CSV, HTML, PAGE_URL

from patchtrace.kbcorrelation import inventory_store as store
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')


@pytest.mark.parametrize('kind', ['inventory', 'support'])
@pytest.mark.parametrize(('route', 'column'), [
    ('read', 'sha256'), ('read', 'body_sha256'), ('list', 'import_id'), ('references', 'sha256'),
])
@pytest.mark.parametrize('invalid', ['a' * 64 + '\0x', '\u00e9' * 64, b'a' * 64],
                         ids=['embedded-nul', 'multibyte-text', 'blob-storage'])
def test_identity_metadata_is_admitted_before_python_projection(tmp_path, kind, route, column, invalid):
    with WorkspaceStore(tmp_path / 'workspace') as ws:
        if kind == 'inventory':
            record, _ = store.add_inventory(ws, CSV, CONTEXT, now=NOW)
            table, read, listing = store.INVENTORY_TABLE, store.get_inventory, store.list_inventories
        else:
            record, _ = store.add_support(ws, HTML, page_url=PAGE_URL, now=NOW)
            table, read, listing = store.SUPPORT_TABLE, store.get_support, store.list_support
        # Change only the disposable fixture to model damaged saved metadata.
        ws.db.execute(f'DROP TRIGGER {table}_update')
        ws.db.execute(f'UPDATE {table} SET {column}=?', (invalid,))
        before = ws.db.execute(f'SELECT * FROM {table}').fetchall()

        def bounded_projection(_cursor, row):
            assert all(value != invalid for value in row), 'unadmitted identity crossed the SQL boundary'
            return row

        ws.db.row_factory = bounded_projection
        try:
            with pytest.raises(KbcStoreError) as caught:
                if route == 'read':
                    read(ws, record.import_id, verify=False)
                elif route == 'list':
                    listing(ws)
                else:
                    store.referenced_raw_hashes(ws)
            assert caught.value.code == 'PT-KBC-VERIFY'
        finally:
            ws.db.row_factory = None
        assert ws.db.execute(f'SELECT * FROM {table}').fetchall() == before
