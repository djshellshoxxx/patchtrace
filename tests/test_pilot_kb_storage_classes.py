"""Malformed SQLite primitives must withhold retained CVRF before shared body decoding."""
from __future__ import annotations

import pytest
from test_pilot_kb_context import CVE, captured, case, gathered

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.pilot.limits import PilotError
from patchtrace.pilot.sources.kb_context import capture
from patchtrace.service import ProjectService

# Import the existing actual import-pair/analysis/rank fixture for this module.
__all__ = ['case']
_COLUMNS = ('id', 'kind', 'project_id', 'project_revision', 'run_id', 'raw_sha256', 'input_digest',
            'status', 'stale', 'created', 'body', 'body_sha256')


def weakened_table(db):
    """A malformed on-disk table can lose its affinities/constraints; no product schema is changed."""
    with db:
        db.execute('CREATE TABLE malformed_context_rows (' + ','.join(_COLUMNS) + ')')
        db.execute('INSERT INTO malformed_context_rows SELECT ' + ','.join(_COLUMNS) + ' FROM enrichment_entries')
        db.execute('DROP TABLE enrichment_entries')
        db.execute('ALTER TABLE malformed_context_rows RENAME TO enrichment_entries')


@pytest.mark.parametrize('column,value,storage_class', [
    ('body', b'{"invalid":"binary storage class"}', 'blob'),
    ('body_sha256', b'0' * 64, 'blob'),
    ('id', b'kb-context:authored-binary-id', 'blob'),
    ('project_id', b'project', 'blob'),
    ('run_id', b'kb', 'blob'),
    ('raw_sha256', b'0' * 64, 'blob'),
    ('input_digest', b'context', 'blob'),
    ('status', b'ok', 'blob'),
    ('created', b'2099-01-01', 'blob'),
    ('project_revision', b'1', 'blob'),
    ('stale', b'0', 'blob'),
    ('id', None, 'null'),
    ('body', None, 'null'),
    ('body_sha256', None, 'null'),
    ('project_revision', None, 'null'),
    ('stale', None, 'null'),
    ('body', 7, 'integer'),
    ('id', 7, 'integer'),
    ('body_sha256', 1.25, 'real'),
    ('project_revision', 1.25, 'real'),
    ('stale', 0.0, 'real'),
])
def test_malformed_row_types_refuse_before_body_loading(case, monkeypatch, column, value, storage_class):
    with ProjectService.open(case) as service:
        before = captured(service)
        assert not before.unavailable and CVE in before.cves
        db = service.store.connection
        weakened_table(db)
        with db:
            # Fixed column names only; values remain bound SQLite parameters.
            db.execute('UPDATE enrichment_entries SET ' + column + '=? WHERE kind=?', (value, 'kb-context'))
        assert db.execute('SELECT typeof(' + column + ') FROM enrichment_entries WHERE kind=?',
                          ('kb-context',)).fetchone() == (storage_class,)
        enrichment = EnrichmentStore(service.store)

        def refuse_decode(*args, **kwargs):
            raise AssertionError('malformed primitive metadata reached shared body decoding')

        monkeypatch.setattr(enrichment, 'entries', refuse_decode)
        first = capture(service, enrichment)
        second = capture(service, enrichment)
        assert first == second and first.unavailable and not first.cves and not first.bundles
        assert first.digest and first.digest != before.digest and first.warnings
        assert all('unknown' in message for message in first.warnings)
        with pytest.raises(PilotError) as error:
            gathered(service, named=(CVE,))
        assert error.value.code == 'PT-PILOT-STALE'
        assert error.value.reason == 'advisory-context-unavailable'


def test_valid_context_and_identity_return_after_corrupt_storage_class_is_restored(case):
    with ProjectService.open(case) as service:
        before = captured(service)
        db = service.store.connection
        (body_sha,), = db.execute('SELECT body_sha256 FROM enrichment_entries WHERE kind=?', ('kb-context',))
        with db:
            db.execute('UPDATE enrichment_entries SET body_sha256=? WHERE kind=?', (body_sha.encode(), 'kb-context'))
        unavailable = captured(service)
        assert unavailable.unavailable and unavailable.digest != before.digest
        with db:
            db.execute('UPDATE enrichment_entries SET body_sha256=? WHERE kind=?', (body_sha, 'kb-context'))
        after = captured(service)
        assert after == before and not after.unavailable and CVE in after.cves
        context = gathered(service, named=(CVE,)).advisory.context(CVE)
        assert context.gate == 'unverified' and context.source_ids
