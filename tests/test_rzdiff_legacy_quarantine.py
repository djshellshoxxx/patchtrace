"""Historical evidence remains readable but ambiguous ownership cannot feed current analysis."""
from __future__ import annotations

from test_secondary_current import _with_store
from test_secondary_runs import run_for
from test_secondary_store import _publish, _set, case  # noqa: F401
from unified_s0_fixtures import addr_map, inputs, loaded, rz, rzdiff_set

from patchtrace.enrichment.storage import Guard
from patchtrace.secondary import load_secondary
from patchtrace.secondary.rzdiff import SINGLETON_KIND
from patchtrace.secondary.store import cache_snapshot, publish_run, select_current
from patchtrace.unified.limits import Budget
from patchtrace.unified.sources.secondary import SecondaryAdapter, usable_sets


def test_legacy_set_is_preserved_but_quarantined(case, capsys):  # noqa: F811
    root, sides, run, revision, pid = case
    original = _set(sides['older'], sides['newer'], '1' * 64)
    unsafe = original.model_copy(update={'matches': original.matches[:1]})
    _publish(root, run, pid, revision, unsafe)
    guard = Guard(pid, run.id, run.raw_sha256, unsafe.file_sha256)
    cached = run_for('f' * 64, match_set_id=unsafe.entry_id, output=unsafe.file_sha256).model_copy(
        update={'older_sha256': sides['older'], 'newer_sha256': sides['newer']})
    _with_store(root, lambda store: publish_run(store, guard, guard, revision, cached))
    before = _with_store(root, load_secondary)
    from patchtrace import cli
    from patchtrace.secondary.evidence_panel_service import select_sets
    chosen, notes = select_current(before)
    _, warnings = select_sets(before)
    assert len(warnings) == 1 and SINGLETON_KIND in warnings[0]
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 4
    assert SINGLETON_KIND in capsys.readouterr().out
    assert chosen == []
    assert len(notes) == 1 and SINGLETON_KIND in notes[0]
    assert _with_store(root, lambda store: cache_snapshot(store, sides['older'], sides['newer'])) == {}
    after = _with_store(root, load_secondary)
    assert len(after) == 1
    assert before[0][1].model_dump_json() == after[0][1].model_dump_json() == unsafe.model_dump_json()


def test_direct_worker_set_cannot_bypass_quarantine():
    source = loaded(rzdiff_set([rz(0x1000, 0x1080)]))
    data = inputs([], secondary=[source])
    out = SecondaryAdapter().atoms(data, addr_map(), Budget())
    assert out.atoms == () and out.nodes == ()
    assert out.limitations == (SINGLETON_KIND,)
    assert len(out.source_refs) == 1
    assert usable_sets(data, {'rz-diff'}) == []


def test_valid_earlier_set_remains_current(case):  # noqa: F811
    root, sides, run, revision, pid = case
    one = _set(sides['older'], sides['newer'], '1' * 64)
    two = one.matches[0].model_copy(update={'newer_address': 0x20})
    safe = one.model_copy(update={'matches': (one.matches[0], two)})
    unsafe = one.model_copy(update={'file_sha256': '2' * 64, 'matches': one.matches[:1]})
    _publish(root, run, pid, revision, safe)
    _publish(root, run, pid, revision, unsafe)
    chosen, notes = select_current(_with_store(root, load_secondary))
    assert [m.file_sha256 for _, m in chosen] == ['1' * 64]
    assert len(notes) == 1 and SINGLETON_KIND in notes[0]
