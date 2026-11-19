"""Strings consumers honor bounded shared provenance, including empty/cache results."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from test_ui_strings_run import make_project, tool_store
from test_ui_strings_source import scan, start, store_floss

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import snapshot as shared
from patchtrace.intelligence.tools.common import RUN_KIND, ToolError, ToolEvidenceSet
from patchtrace.strings.cli import compute
from patchtrace.strings.contracts import StringsError


def args(source='floss'):
    return SimpleNamespace(source=source, anchors=None, min_length=4)


@pytest.mark.parametrize('empty', [False, True])
def test_stored_cache_and_empty_results_do_not_require_a_new_raw_file(qtbot, tmp_path, empty):
    service = make_project(tmp_path, 'floss-static')
    try:
        store_floss(tmp_path, service, 'older', 'newer')
        store = tool_store(service)
        for side in ('older', 'newer'):
            run, evidence = store.latest('floss', side)
            if empty:
                run = run.model_copy(update={'run_id': f'empty-{side}', 'status': 'none-found', 'evidence_count': 0,
                                             'raw_sidecar': None, 'stdout_digest': None})
                evidence = ToolEvidenceSet(run_id=run.run_id, engine='floss', side=side,
                                           artifact_sha256=run.input_artifact_hash,
                                           cache_key=run.cache_key, config_digest=run.config_digest,
                                           analysis={'types': 'static', 'min_length': 4, 'empty_output': 1})
                store.publish_run(run)
                store.publish_evidence(evidence)
            cached = run.model_copy(update={'run_id': f'cached-{side}', 'cache_hit': True,
                                            'raw_sidecar': None, 'stdout_digest': None})
            store.publish_run(cached)
        computed = compute(args(), service, threading.Event())
        assert computed.sources == {'older': 'floss', 'newer': 'floss'}
        for table in computed.tables.values():
            assert table.basis.parts[0].raw_sha256 is None
            assert table.basis.parts[0].normalized_evidence_sha256 is not None
            assert (len(table) == 0) is empty
        controller = start(qtbot, service, choice='floss')
        scan(qtbot, controller)
        assert controller.error is None and controller.loaded is not None
        assert controller.loaded.delta == computed.delta
    finally:
        service.close()


def test_corrupt_selected_row_is_not_builtin_fallback_or_a_false_empty(qtbot, tmp_path):
    service = make_project(tmp_path, 'floss-static')
    try:
        store_floss(tmp_path, service, 'older', 'newer')
        controller = start(qtbot, service)
        scan(qtbot, controller)
        prior = controller.loaded
        run = next(entry for entry in EnrichmentStore(service.store).entries(RUN_KIND)
                   if entry.body['side'] == 'older')
        service.store.connection.execute('UPDATE enrichment_entries SET raw_sha256=? WHERE id=?', ('f' * 64, run.id))
        with pytest.raises(ToolError):
            compute(args('auto'), service, threading.Event())
        scan(qtbot, controller)
        assert controller.error[0] == 'PT-TOOL-OUTPUT' and controller.loaded is prior
    finally:
        service.close()


def test_builtin_consumers_never_construct_or_capture_a_tool_store(qtbot, tmp_path, monkeypatch):
    from patchtrace.intelligence.tools.store import ToolStore
    service = make_project(tmp_path, 'floss-static')
    try:
        def forbidden(*a, **kw):
            pytest.fail('built-in selection must not inspect stored tool evidence')
        monkeypatch.setattr(shared, 'capture_tool_sources', forbidden)
        monkeypatch.setattr(ToolStore, '__init__', forbidden)
        computed = compute(args('builtin'), service, threading.Event())
        controller = start(qtbot, service, choice='builtin')
        scan(qtbot, controller)
        assert controller.loaded.delta == computed.delta
    finally:
        service.close()


def test_precancelled_cli_composition_does_not_read_artifacts_or_tool_evidence(tmp_path, monkeypatch):
    from patchtrace.strings import pairing
    service = make_project(tmp_path, 'floss-static')
    try:
        def forbidden(*a, **kw):
            pytest.fail('cancelled composition must not inspect artifacts or evidence')
        monkeypatch.setattr(shared, 'capture_tool_sources', forbidden)
        monkeypatch.setattr(pairing, 'inspect_image', forbidden)
        cancel = threading.Event()
        cancel.set()
        with pytest.raises(StringsError) as caught:
            compute(args(), service, cancel)
        assert caught.value.code == 'PT-STR-CANCEL'
    finally:
        service.close()
