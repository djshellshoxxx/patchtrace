"""R5 store: append-only `rule-*` rows, accept as a separate immutable version, sidecar matrices, crash repair."""
from __future__ import annotations

import dataclasses
import threading
from types import SimpleNamespace

import pytest

yara_x = pytest.importorskip('yara_x')

import yarax_fixtures as fx  # noqa: E402
from intel_tools_support import image_getter  # noqa: E402
from test_intel_tools_pe import PAIRS  # noqa: E402

from patchtrace.enrichment.storage import DERIVED_KINDS, KINDS, EnrichmentStore  # noqa: E402
from patchtrace.service import ProjectService  # noqa: E402
from patchtrace.yarax import candidates, matrix  # noqa: E402
from patchtrace.yarax import store as rule_store  # noqa: E402
from patchtrace.yarax.adapters import tools_delta  # noqa: E402
from patchtrace.yarax.contracts import Gate  # noqa: E402
from patchtrace.yarax.errors import RulesError  # noqa: E402
from patchtrace.yarax.limits import LIMITS  # noqa: E402
from patchtrace.yarax.synth import parse_rule  # noqa: E402

NOW = '2026-10-14T10:00:00Z'


@pytest.fixture
def project(tmp_path):
    """A real project holding the synthetic floss-static pair, with a rule store and real candidates."""
    older, newer = PAIRS['floss-static']()
    files = {}
    for side, data in (('older', older), ('newer', newer)):
        files[side] = tmp_path / f'{side}.exe'
        files[side].write_bytes(data)
    service = ProjectService.create(files['older'], files['newer'], 'rules', tmp_path / 'case')
    info = service.project
    store = rule_store.RuleStore(EnrichmentStore(service.store), service.root, info.id, info.revision)
    get, close = image_getter(tmp_path)
    delta, readers = fx.floss_delta(get, 'floss-static')
    pair = fx.pair_source(get, 'floss-static', match_id='m1', category='modified').model_copy(
        update={'project_id': info.id})
    found = candidates.propose(pair, writer=matrix.synth_writer(), engine=fx.ENGINE,
                               strings=tools_delta.FlossStringSource(delta, readers))
    try:
        yield SimpleNamespace(service=service, store=store, pair=pair, candidates={c.direction: c for c in found},
                              tmp=tmp_path)
    finally:
        close()
        service.close()


def reopen(project):
    info = project.service.project
    return rule_store.RuleStore(EnrichmentStore(project.service.store), project.service.root, info.id, info.revision)


def test_rule_kinds_are_reserved_and_never_derived():
    kinds = {'rule-candidate', 'rule-decision', 'rule-version', 'rule-test', 'rule-export'}
    assert kinds <= KINDS and not kinds & set(DERIVED_KINDS)


def test_a_candidate_is_stored_once_and_reads_back_equal(project):
    candidate = project.candidates['older']
    assert project.store.add_candidate(candidate) == project.store.add_candidate(candidate) == \
        f'rule-candidate:{candidate.candidate_id}'
    assert reopen(project).candidates() == [candidate]


def test_stored_rows_are_never_rewritten(project):
    candidate = project.candidates['older']
    project.store.add_candidate(candidate)
    changed = candidate.model_copy(update={'gates': (Gate(gate_id='sep', state='pass'),)})
    with pytest.raises(RulesError) as caught:
        project.store.add_candidate(changed)
    assert caught.value.code == 'PT-RULE-INTEGRITY'
    assert reopen(project).candidates() == [candidate]


def test_accept_saves_a_decision_and_the_first_version_without_exporting(project):
    candidate = project.candidates['newer']
    decision, version = project.store.decide(candidate, 'accept', label='Length check added', cve=['CVE-2026-0001'],
                                             kb=['KB5000001'], now=lambda: NOW)
    assert version.version == 1 and version.supersedes is None and version.created_at == NOW
    parsed = parse_rule(version.rule_text)
    meta = dict(parsed.meta)
    assert meta['patchtrace_version'] == 1 and meta['analyst_label'] == 'Length check added'
    assert meta['cve'] == 'CVE-2026-0001' and meta['kb'] == 'KB5000001'
    assert version.rule_sha256 != candidate.rule_sha256   # label and anchors are part of the saved text
    assert decision.decision_id == version.decision_id and project.store.exports() == []
    rows = reopen(project)
    assert [v.version_id for v in rows.versions()] == [version.version_id] and rows.decisions() == [decision]


def test_accepting_needs_a_label(project):
    with pytest.raises(RulesError) as caught:
        project.store.decide(project.candidates['older'], 'accept', label='  ')
    assert caught.value.code == 'PT-RULE-INPUT' and project.store.versions() == []


@pytest.mark.parametrize('action', ['reject', 'defer', 'archive'], ids=['reject', 'defer', 'archive'])
def test_other_decisions_save_no_version(project, action):
    decision, version = project.store.decide(project.candidates['older'], action, note='later', now=lambda: NOW)
    assert version is None and decision.action == action and project.store.versions() == []
    wanted = {'reject': 'Rejected', 'defer': 'Deferred', 'archive': 'Archived'}[action]
    assert rule_store.lineage_status(project.store)[project.candidates['older'].candidate_id] == wanted


def test_repeating_the_same_accept_is_idempotent(project):
    candidate = project.candidates['older']
    first = project.store.decide(candidate, 'accept', label='Debug dump removed', now=lambda: NOW)
    again = project.store.decide(candidate, 'accept', label='Debug dump removed', now=lambda: '2026-10-14T11:00:00Z')
    assert first == again and len(project.store.versions()) == len(project.store.decisions()) == 1


def test_a_crash_between_decision_and_version_is_repaired_by_repeating(project, monkeypatch):
    candidate = project.candidates['newer']

    def crash(_version):
        raise OSError('disk gone')
    monkeypatch.setattr(project.store, 'add_version', crash)
    with pytest.raises(OSError):
        project.store.decide(candidate, 'accept', label='Length check', now=lambda: NOW)
    assert len(project.store.decisions()) == 1 and project.store.versions() == []
    monkeypatch.undo()
    _decision, version = project.store.decide(candidate, 'accept', label='Length check', now=lambda: NOW)
    assert version.version == 1 and len(project.store.decisions()) == 1 and len(project.store.versions()) == 1


def test_a_new_decision_on_the_lineage_is_version_two_that_supersedes_version_one(project):
    candidate = project.candidates['older']
    _d1, v1 = project.store.decide(candidate, 'accept', label='first', now=lambda: NOW)
    _d2, v2 = project.store.decide(candidate, 'accept', label='second label', now=lambda: NOW)
    assert (v2.version, v2.supersedes) == (2, v1.version_id) and v2.lineage_id == v1.lineage_id
    assert parse_rule(v2.rule_text).meta[1] == ('patchtrace_version', 2)
    assert [v.version for v in project.store.versions(candidate.lineage_id)] == [1, 2]
    assert project.store.versions(candidate.lineage_id)[0].rule_text == v1.rule_text   # immutable


def test_the_version_cap_is_enforced(project):
    capped = rule_store.RuleStore(project.store.enrichment, project.store.project_dir, project.store.project_id,
                                  project.store.revision, dataclasses.replace(LIMITS, versions_per_lineage=1))
    candidate = project.candidates['older']
    capped.decide(candidate, 'accept', label='one', now=lambda: NOW)
    with pytest.raises(RulesError) as caught:
        capped.decide(candidate, 'accept', label='two', now=lambda: NOW)
    assert caught.value.code == 'PT-RULE-LIMIT'


def test_a_failed_hard_gate_refuses_accept_but_unknown_does_not(project):
    candidate = project.candidates['older']
    assert any(g.state == 'unknown' for g in candidate.gates)
    failing = candidate.model_copy(update={'gates': tuple(
        Gate(gate_id='sep', state='fail', measured='1/1') if g.gate_id == 'sep' else g for g in candidate.gates)})
    with pytest.raises(RulesError) as caught:
        project.store.decide(failing, 'accept', label='nope')
    assert caught.value.code == 'PT-RULE-GATE' and 'sep' in caught.value.message and project.store.versions() == []
    assert project.store.decide(candidate, 'accept', label='fine')[1] is not None


def run_for(project, version, cells=1):
    anchors = project.service.project.artifacts
    older = matrix.file_target(project.service.root / anchors[0].relative_path, 'older-anchor', None,
                               sha256=anchors[0].sha256, size=anchors[0].size)
    rule = matrix.MatrixRule(name=parse_rule(version.rule_text).name, text=version.rule_text, direction='older',
                             version_id=version.version_id, rule_sha256=version.rule_sha256)
    fake = SimpleNamespace(scan=lambda rules, targets: (fx.ENGINE, tuple(
        matrix.CellResult(rule_name=r.name, target_id=t.target_id, state='hit', hits=1, rvas=(0x1000,))
        for r in rules for t in targets)))
    engine = matrix.Engine(probe=lambda: fx.ENGINE, lint=lambda rules: (fx.ENGINE, ()), scan=fake.scan)
    return matrix.run_matrix([rule], [older], engine=engine, stamp=fx.ENGINE, cancel=threading.Event(), run_id='run-a')


def test_a_test_is_found_by_version_and_the_newest_wins(project):
    _d, version = project.store.decide(project.candidates['older'], 'accept', label='x', now=lambda: NOW)
    assert project.store.latest_test(version.version_id) is None
    run = run_for(project, version)
    project.store.add_test(run, [version])
    found, at = reopen(project).latest_test(version.version_id)
    assert found == run and at.endswith('Z') and len(at) == 20


def test_a_large_grid_goes_to_a_hash_checked_sidecar(project):
    _d, version = project.store.decide(project.candidates['older'], 'accept', label='x', now=lambda: NOW)
    small = rule_store.RuleStore(project.store.enrichment, project.store.project_dir, project.store.project_id,
                                 project.store.revision, dataclasses.replace(LIMITS, matrix_inline_bytes=100))
    run = run_for(project, version)
    small.add_test(run, [version])
    sidecars = list((project.service.root / 'rules' / 'tests').glob('*.json'))
    assert len(sidecars) == 1 and small.latest_test(version.version_id)[0] == run
    row = next(e for e in small.enrichment.entries('rule-test') if e.body.get('kind') == 'matrix')
    assert 'record' not in row.body and row.body['sidecar_sha256'] == sidecars[0].stem
    sidecars[0].write_bytes(sidecars[0].read_bytes().replace(b'run-a', b'run-b'))
    with pytest.raises(RulesError) as caught:
        small.latest_test(version.version_id)
    assert caught.value.code == 'PT-RULE-INTEGRITY'


def test_checkpoints_keep_scanned_cells_only(project):
    ok = matrix.CellResult(rule_name='PT_0123456789ab_older', target_id='t1', state='no-hit')
    bad = matrix.CellResult(rule_name='PT_0123456789ab_older', target_id='t2', state='timeout', reason='slow')
    older, newer = project.pair.older_sha256, project.pair.newer_sha256
    project.store.add_checkpoint('k' * 64, older, newer, [ok, bad])
    project.store.add_checkpoint('k' * 64, older, newer, [ok, bad])   # same content: one row
    project.store.add_checkpoint('j' * 64, older, newer, [bad])       # nothing scanned: nothing stored
    assert reopen(project).checkpoint_cells('k' * 64) == [ok] and reopen(project).checkpoint_cells('j' * 64) == []


def test_rows_of_a_newer_client_keep_their_extra_fields_and_still_read(project):
    candidate = project.candidates['older'].model_copy(update={'candidate_id': 'c' * 64})
    record = {**candidate.model_dump(mode='json'), 'future_field': {'a': 1}}
    project.store._append(rule_store.CANDIDATE, candidate.candidate_id, project.pair.older_sha256,
                          project.pair.newer_sha256, 'proposed', {'record': record})
    assert [c.candidate_id for c in reopen(project).candidates()] == ['c' * 64]


def test_a_row_that_fails_its_integrity_hash_is_skipped_not_served(project):
    candidate = project.candidates['older']
    project.store.add_candidate(candidate)
    project.store.add_candidate(project.candidates['newer'])
    enrichment_db = project.store.enrichment._db
    with enrichment_db:
        enrichment_db.execute("UPDATE enrichment_entries SET body=body||' ' WHERE id=?",
                              (f'rule-candidate:{candidate.candidate_id}',))
    assert [c.direction for c in reopen(project).candidates()] == ['newer']


def test_rows_belong_to_their_project_only(project):
    project.store.add_candidate(project.candidates['older'])
    stranger = rule_store.RuleStore(project.store.enrichment, project.store.project_dir, 'other-project',
                                    project.store.revision)
    assert stranger.candidates() == []
