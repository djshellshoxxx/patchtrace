from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from patchtrace.alignment import align_lines, diff_hunks
from patchtrace.evidence import build_context
from patchtrace.ingestion import inspect_artifact, safe_path, sha256_file
from patchtrace.models import AnalysisRun, InterpretationRun
from patchtrace.normalization import normalize_ghidriff
from patchtrace.sample import sample_diff, synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def pair(tmp_path):
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    return older, newer


@pytest.fixture
def project(tmp_path, pair):
    service = ProjectService.create(*pair, 'Comparison', tmp_path / 'project')
    yield service
    service.close()


def raw_file(service, tmp_path, diff=None):
    path = tmp_path / 'diff.ghidriff.json'
    path.write_text(json.dumps(diff or sample_diff(service.project)), encoding='utf-8')
    return path


def test_immutable_copies_static_validation_and_names(tmp_path):
    source = tmp_path / '$(touch pwned);`echo injected`.dll'
    source.write_bytes(synthetic_pe())
    artifact = inspect_artifact(source, 'older', tmp_path / 'project')
    assert artifact.name == source.name
    assert sha256_file(source) == artifact.sha256
    copy_path = safe_path(tmp_path / 'project', artifact.relative_path)
    source.write_bytes(b'original changed')
    assert copy_path.read_bytes() == synthetic_pe()
    assert not (tmp_path / 'pwned').exists()
    bad = tmp_path / 'bad.dll'
    bad.write_bytes(b'not a PE')
    with pytest.raises(ValueError, match='PT-INPUT'):
        inspect_artifact(bad, 'newer', tmp_path / 'project')
    wrong_machine = bytearray(synthetic_pe())
    wrong_machine[0x84:0x86] = b'\x4c\x01'
    bad.write_bytes(wrong_machine)
    with pytest.raises(ValueError, match='AMD64'):
        inspect_artifact(bad, 'newer', tmp_path / 'project')
    malformed = bytearray(synthetic_pe())
    malformed[0x3c:0x40] = b'\xff\xff\xff\xff'
    bad.write_bytes(malformed)
    with pytest.raises(ValueError, match='offset'):
        inspect_artifact(bad, 'newer', tmp_path / 'project')


def test_roundtrip_raw_identity_history_backup_and_relocation(project, tmp_path):
    raw = raw_file(project, tmp_path)
    project.import_diff(raw)
    assert {m.category for m in project.project.matches} == {'added', 'removed', 'modified'}
    run = project.project.runs[-1]
    assert safe_path(project.root, run.raw_path).read_bytes() == raw.read_bytes()
    assert run.raw_sha256 == sha256_file(raw)
    assert all(f.assembly is None for m in project.project.matches for f in m.older + m.newer)
    match = project.project.matches[-1]
    project.review_match(match.id, 'accepted')
    project.annotate(match.id, '<script>alert(1)</script> $(touch should-not-run)')
    expected = project.project.model_dump()
    history = project.store.history()
    assert len(history) == 4
    destination = project.backup(tmp_path / 'relocated')
    with ProjectService.open(destination) as restored:
        assert restored.project.model_dump() == expected
        assert restored.root != project.root
        assert restored.store.history() == history
    project.close()
    with ProjectService.open(project.root) as reopened:
        assert reopened.project.model_dump() == expected


def test_exclusive_writer_and_close_releases_lock(project):
    with pytest.raises(ValueError, match='locked'):
        ProjectService.open(project.root)
    project.close()
    with ProjectService.open(project.root) as reopened:
        assert reopened.project.name == 'Comparison'


def test_unknown_schema_and_forged_ordered_input_rejected_without_commit(project, tmp_path):
    before = project.project.model_dump()
    malformed = {'functions': {'added': [], 'modified': []},
                 'old_meta': {'SHA256': project.project.artifacts[0].sha256},
                 'new_meta': {'SHA256': project.project.artifacts[1].sha256}}
    for diff in [malformed, {'not_functions': []}, sample_diff(project.project) | {'future_field': {}}]:
        with pytest.raises(ValueError, match='PT-SCHEMA'):
            project.import_diff(raw_file(project, tmp_path, diff))
        assert project.project.model_dump() == before
    forged = sample_diff(project.project)
    forged['old_meta']['Executable SHA256'] = project.project.artifacts[1].sha256
    with pytest.raises(ValueError, match='hash does not match'):
        project.import_diff(raw_file(project, tmp_path, forged))
    assert project.project.model_dump() == before
    assert len(project.store.history()) == 1


def test_normalizer_rejects_malformed_records_and_never_treats_addresses_as_matches(project):
    run = AnalysisRun(status='completed')
    candidate = project.project.model_copy(deep=True)
    candidate.runs.append(run)
    raw = sample_diff(candidate)
    raw['functions']['added'] = ['a bare name is not an enhanced function']
    with pytest.raises(ValueError, match='enhanced function'):
        normalize_ghidriff(raw, candidate, run.id)
    raw = sample_diff(candidate)
    raw['functions']['modified'][0]['new']['address'] = raw['functions']['modified'][0]['old']['address']
    result = normalize_ghidriff(raw, candidate, run.id)
    assert next(m for m in result if m.newer and m.newer[0].name == 'read_item').category == 'modified'
    assert next(m for m in result if m.newer and m.newer[0].name == 'read_item').newer[0].metadata[
        'instructions_hash'] == -17200333


def test_sample_reinterpret_same_context_and_forged_evidence(tmp_path):
    with ProjectService.sample(tmp_path / 'sample') as service:
        assert service.project.sample
        first = service.project.interpretations[0]
        context = build_context(service.project, first.context.match_ids)
        assert context == first.context
        service.add_interpretation(InterpretationRun(context=context, provider='test', model='test',
                                                     status='completed', findings=[]))
        assert len(service.project.interpretations) == 2
        bad = context.model_copy(deep=True)
        bad.evidence[0].text = 'invented evidence'
        with pytest.raises(ValueError, match='context|preview|evidence|conflicting'):
            service.add_interpretation(InterpretationRun(context=bad, provider='test', model='test',
                                                         status='completed', findings=[]))
        assert len(service.project.interpretations) == 2


def test_manual_split_remainder_stale_orientation_and_roundtrip(tmp_path):
    root = tmp_path / 'sample'
    with ProjectService.sample(root) as service:
        read_item = next(m for m in service.project.matches if m.older and m.older[0].name == 'read_item')
        added = next(m for m in service.project.matches if m.category == 'added')
        service.correct_match(read_item.id, [read_item.older[0].id],
                              [read_item.newer[0].id, added.newer[0].id], 'split', 'Analyst checked the wrapper')
        corrected = next(m for m in service.project.matches if m.id == read_item.id)
        assert corrected.manual and len(corrected.newer) == 2 and corrected.category == 'split'
        assert service.project.interpretations[0].context.stale
        assert service.project.interpretations[0].findings[0].stale
        assert any(a.kind == 'match-override' and 'previous_matches' in a.text for a in service.project.annotations)
        service.swap_orientation()
        assert next(m for m in service.project.matches if m.id == read_item.id).category == 'merged'
        expected = service.project.model_dump()
    with ProjectService.open(root) as restored:
        assert restored.project.model_dump() == expected


def test_manual_correction_wrong_side_or_run_does_not_commit(project, tmp_path):
    project.import_diff(raw_file(project, tmp_path))
    match = next(m for m in project.project.matches if m.category == 'modified')
    before = project.project.model_dump()
    with pytest.raises(ValueError, match='another side'):
        project.correct_match(match.id, [match.newer[0].id], [match.older[0].id], 'modified', 'wrong side')
    with pytest.raises(ValueError, match='reason'):
        project.correct_match(match.id, [match.older[0].id], [match.newer[0].id], 'modified', '')
    assert project.project.model_dump() == before


def test_worker_prepares_without_sqlite_then_main_thread_commits(project, tmp_path):
    raw = raw_file(project, tmp_path)
    before = project.project.model_dump()
    with ThreadPoolExecutor(max_workers=1) as executor:
        prepared = executor.submit(project.prepare_import, raw).result()
    assert project.project.model_dump() == before
    assert len(project.store.history()) == 1
    forged = copy.copy(prepared)
    with pytest.raises(ValueError, match='not prepared'):
        project.apply_import(forged)
    project.apply_import(prepared)
    assert len(project.project.matches) == 4
    assert len(project.store.history()) == 2


def test_recovery_interrupted_run_and_terminal_transaction(project):
    run = AnalysisRun(status='running')
    project.project.runs.append(run)
    project.save()
    root = project.root
    project.close()
    with ProjectService.open(root) as recovered:
        assert recovered.project.runs[0].status == 'failed'
        assert 'interrupted' in recovered.project.runs[0].error
        failed = AnalysisRun(status='cancelled', error='Analyst cancelled')
        recovered.record_terminal_run(failed)
        assert recovered.project.runs[-1].status == 'cancelled'
        with pytest.raises(ValueError, match='identical input'):
            recovered.record_terminal_run(AnalysisRun(status='identical'))


def test_corruption_and_traversal_fail_closed(project):
    with pytest.raises(ValueError, match='relative'):
        safe_path(project.root, '../outside.dll')
    project.close()
    with sqlite3.connect(project.root / 'project.sqlite3') as db:
        db.execute("UPDATE current_snapshot SET payload='{}'")
    with pytest.raises(ValueError, match='hash failed'):
        ProjectService.open(project.root)


def test_aligned_original_line_ranges_do_not_fabricate_code():
    rows = align_lines('a\nb\nc', 'a\nnew\nb\nc')
    assert rows == [('a', 'a', 'equal'), (None, 'new', 'insert'), ('b', 'b', 'equal'), ('c', 'c', 'equal')]
    hunks = diff_hunks('a\nb', 'a\nc\nd', 'match')
    assert [(h.old_start, h.old_end, h.new_start, h.new_end) for h in hunks] == [(0, 1, 0, 1), (1, 2, 1, 3)]
    assert align_lines(None, '') == []


def test_tampered_content_restored_mtime_invalidates_verification_cache(project):
    import os
    artifact = project.project.artifacts[0]
    path = safe_path(project.root, artifact.relative_path)
    before = path.stat()
    # A same-length overwrite and restored last-write timestamp must still force a fresh SHA-256.
    content = bytearray(path.read_bytes())
    content[-1] ^= 1
    path.chmod(0o644)
    path.write_bytes(content)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ValueError, match='changed'):
        project.save()
    assert len(project.store.history()) == 1


def test_json_nesting_failure_is_tagged(project, tmp_path):
    nested = tmp_path / 'nested.json'
    nested.write_text('[' * 20000 + '0' + ']' * 20000, encoding='utf-8')
    with pytest.raises(ValueError, match='PT-SCHEMA: JSON nesting'):
        project.import_diff(nested)
    assert len(project.store.history()) == 1


def test_exact_upstream_neighbor_can_be_saved_and_forged_scope_rejected(project, tmp_path):
    from patchtrace.evidence import context_digest
    raw = sample_diff(project.project)
    raw['functions']['added'][0]['fullname'] = 'example::report_invalid_index'
    project.import_diff(raw_file(project, tmp_path, raw))
    selected = next(m for m in project.project.matches if m.category == 'modified' and m.newer[0].name == 'read_item')
    context = build_context(project.project, [selected.id])
    assert any(ref.function_id == project.project.matches[0].newer[0].id for ref in context.evidence)
    project.add_interpretation(InterpretationRun(context=context, provider='test', model='test', status='completed'))
    # Recompute a digest over a malicious scope: digests authenticate exact bytes, not authority.
    unrelated = next(m for m in project.project.matches if m.newer and m.newer[0].name == 'get_version')
    forged = context.model_copy(deep=True)
    payload = json.loads(forged.payload)
    payload['matches'][0]['context_function_ids'].append(unrelated.newer[0].id)
    forged.payload = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    forged.digest = context_digest(forged.payload, forged.omitted)
    forged.id = 'ctx-' + forged.digest
    with pytest.raises(ValueError, match='scope differs'):
        project.add_interpretation(InterpretationRun(context=forged, provider='test', model='test', status='completed'))
    assert len(project.project.interpretations) == 1


def test_finding_citations_cannot_cross_selected_match_scope(project, tmp_path):
    from patchtrace.models import Finding, Hypothesis
    project.import_diff(raw_file(project, tmp_path))
    matches = [m for m in project.project.matches if m.category == 'modified']
    context = build_context(project.project, [m.id for m in matches])
    read_item = next(m for m in matches if m.newer[0].name == 'read_item')
    version = next(m for m in matches if m.newer[0].name == 'get_version')
    unrelated = next(ref.id for ref in context.evidence if ref.function_id == version.newer[0].id)
    finding = Finding(context_id=context.id, match_ids=[read_item.id], summary='Forged unrelated citation',
                      fix_purpose='Not established', category='unknown',
                      hypothesis=Hypothesis(explanation='Unrelated version evidence', supporting=[unrelated]))
    with pytest.raises(ValueError, match='cites unknown evidence'):
        project.add_interpretation(InterpretationRun(context=context, provider='test', model='test',
                                                     status='completed', findings=[finding]))
    assert not project.project.interpretations
