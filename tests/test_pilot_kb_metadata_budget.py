"""The retained-context allocation budget includes all selected row fields before loading."""
from __future__ import annotations

import pytest
from test_pilot_kb_context import CVE, captured, case, original, publish, revised

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.pilot.sources import kb_context
from patchtrace.service import ProjectService

__all__ = ['case']
_COLUMNS = ('id', 'kind', 'project_id', 'project_revision', 'run_id', 'raw_sha256', 'input_digest',
            'status', 'stale', 'created', 'body', 'body_sha256')


def stored_sizes(db):
    rows = db.execute('SELECT ' + ','.join(_COLUMNS) + ' FROM enrichment_entries WHERE kind=?',
                      ('kb-context',)).fetchall()
    return [sum(len(value.encode('utf-8') if isinstance(value, str) else str(value).encode('ascii'))
                for value in row) for row in rows]


def refused_before_loading(service, monkeypatch):
    enrichment = EnrichmentStore(service.store)

    def refuse(*args, **kwargs):
        raise AssertionError('over-budget retained row reached full shared-row loading')

    monkeypatch.setattr(enrichment, 'entries', refuse)
    snapshot = kb_context.capture(service, enrichment)
    assert snapshot.unavailable and not snapshot.cves and not snapshot.bundles
    assert snapshot.digest and snapshot.warnings and any('byte limit' in note for note in snapshot.warnings)
    assert kb_context.capture(service, enrichment) == snapshot


@pytest.mark.parametrize('column', ['id', 'project_id', 'run_id', 'raw_sha256', 'input_digest',
                                   'status', 'created', 'body', 'body_sha256'])
def test_every_variable_text_column_is_bounded_before_loading(case, monkeypatch, column):
    with ProjectService.open(case) as service:
        cap = sum(stored_sizes(service.store.connection)) + 2048
        monkeypatch.setattr(kb_context, 'MAX_BYTES', cap)
        payload = 'é' * (cap // 2 + 1)  # characters fit; UTF-8 bytes exceed the whole budget
        assert len(payload) <= cap < len(payload.encode('utf-8'))
        with service.store.connection as db:
            db.execute('UPDATE enrichment_entries SET ' + column + '=? WHERE kind=?', (payload, 'kb-context'))
        refused_before_loading(service, monkeypatch)


def test_embedded_nul_does_not_truncate_counted_metadata_bytes(case, monkeypatch):
    with ProjectService.open(case) as service:
        cap = sum(stored_sizes(service.store.connection)) + 2048
        monkeypatch.setattr(kb_context, 'MAX_BYTES', cap)
        with service.store.connection as db:
            db.execute('UPDATE enrichment_entries SET created=? WHERE kind=?', ('stamp\0' + 'x' * cap, 'kb-context'))
        refused_before_loading(service, monkeypatch)


def test_multiple_individually_bounded_rows_share_one_metadata_budget(case, monkeypatch):
    with ProjectService.open(case) as service:
        publish(service, revised(original(service)))
        db = service.store.connection
        (body_total,) = db.execute('SELECT sum(length(CAST(body AS BLOB))) FROM enrichment_entries WHERE kind=?',
                                  ('kb-context',)).fetchone()
        with db:
            db.execute('UPDATE enrichment_entries SET created=? WHERE kind=?', ('x' * body_total, 'kb-context'))
        sizes = stored_sizes(db)
        cap = max(body_total, *sizes)
        assert len(sizes) == 2 and body_total <= cap and max(sizes) <= cap < sum(sizes)
        monkeypatch.setattr(kb_context, 'MAX_BYTES', cap)
        refused_before_loading(service, monkeypatch)


@pytest.mark.parametrize('row_count', [1, 2])
def test_exact_combined_limit_preserves_valid_capture_but_one_byte_less_refuses(case, monkeypatch, row_count):
    with ProjectService.open(case) as service:
        if row_count == 2:
            publish(service, revised(original(service)))
        with service.store.connection as db:
            db.execute('UPDATE enrichment_entries SET created=? WHERE kind=?', ('時刻-😀', 'kb-context'))
        before = captured(service)
        assert not before.unavailable and CVE in before.cves
        sizes = stored_sizes(service.store.connection)
        assert len(sizes) == row_count
        monkeypatch.setattr(kb_context, 'MAX_BYTES', sum(sizes))
        assert captured(service) == before
        monkeypatch.setattr(kb_context, 'MAX_BYTES', sum(sizes) - 1)
        refused_before_loading(service, monkeypatch)
