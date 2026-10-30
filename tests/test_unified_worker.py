"""SPEC-31 S0b compute step, exchange files and the hidden worker entry (01 s4-s5, 08 G-U1/G-U4, 02 s10 item 3).
Synthetic inputs only; the worker is called in process here (the real child is exercised in test_unified_pipeline)."""
from __future__ import annotations

import dataclasses
import json
import threading
from pathlib import Path

import pytest
from unified_s0_fixtures import (
    NEW_SHA,
    RAW_SHA,
    addr_map,
    bd,
    bindiff_set,
    func,
    inputs,
    loaded,
    match,
    raw_ok,
    rich_inputs,
    shuffled,
    va,
    with_raw_sha,
    write_worker_request,
)

from patchtrace.unified import compute, exchange, store, worker
from patchtrace.unified.compute import compute_result, plan_identity
from patchtrace.unified.exchange import ALL_SOURCES, StageEvent, WorkerRequest
from patchtrace.unified.limits import (
    CONTENT_LIMIT_FIELDS,
    DEFAULT_LIMITS,
    ERROR_CODES,
    OPERATIONAL_LIMIT_FIELDS,
    Budget,
    BudgetExhausted,
    UnifiedError,
)
from patchtrace.unified.sources import RawGhidriff

FIXED = '2026-01-01T00:00:00+00:00'


def run(data, directory: Path, **kw):
    directory.mkdir()
    kw.setdefault('created_utc', FIXED)
    return compute_result(data, addr_map(), result_dir=directory, **kw)


def files_of(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir())}


def rows_of(directory: Path, manifest):
    return list(store.read_rows(directory, manifest))


# --- G-U4: determinism and symmetry ------------------------------------------------------------------------------

def test_two_runs_and_any_input_order_give_byte_identical_results(tmp_path):
    data = rich_inputs()
    run(data, tmp_path / 'a')
    run(data, tmp_path / 'again')
    assert files_of(tmp_path / 'again') == files_of(tmp_path / 'a')
    for seed in (1, 2, 3):
        run(shuffled(data, seed), tmp_path / f's{seed}')
        assert files_of(tmp_path / f's{seed}') == files_of(tmp_path / 'a')


def test_only_the_creation_time_differs_between_runs(tmp_path):
    first = run(rich_inputs(), tmp_path / 'a', created_utc='2026-01-01T00:00:00+00:00')
    second = run(rich_inputs(), tmp_path / 'b', created_utc='2027-06-30T12:00:00+00:00')
    a, b = files_of(tmp_path / 'a'), files_of(tmp_path / 'b')
    assert a['rows.jsonl.gz'] == b['rows.jsonl.gz'] and a['facts.jsonl.gz'] == b['facts.jsonl.gz']
    assert first.result_id == second.result_id
    docs = [json.loads(files[store.MANIFEST]) for files in (a, b)]
    for doc in docs:
        doc.pop('created_utc')
    assert docs[0] == docs[1]


def test_swapping_older_and_newer_mirrors_the_rows(tmp_path):
    forward = run(rich_inputs(False), tmp_path / 'fwd')
    backward = run(rich_inputs(True), tmp_path / 'bwd')
    classes = {'call-added': 'call-removed', 'call-removed': 'call-added'}
    sides = {'older-only': 'newer-only', 'newer-only': 'older-only'}

    def table(directory, manifest, mirror):
        out = {}
        for row in rows_of(directory, manifest):
            older, newer = tuple(s.rva for s in row.older), tuple(s.rva for s in row.newer)
            key = (newer, older) if mirror else (older, newer)
            decision = sides.get(row.decision, row.decision) if mirror else row.decision
            kinds = tuple(sorted(classes.get(c, c) if mirror else c for c in row.change_classes))
            out[key] = (decision, row.materiality, kinds)
        return out
    mirrored = table(tmp_path / 'fwd', forward, True)
    assert len(mirrored) == forward.counts.total() == 10  # every row counts: nothing is compared against nothing
    assert mirrored == table(tmp_path / 'bwd', backward, False)
    assert {v[0] for v in mirrored.values()} >= {'matched', 'contested', 'candidate', 'older-only', 'newer-only'}
    assert forward.counts.decisions.older_only == backward.counts.decisions.newer_only
    assert forward.counts.decisions.newer_only == backward.counts.decisions.older_only


def test_the_same_build_against_itself_invents_no_change(tmp_path):
    """G-U1 (X versus X) for what S0 can see: everything matches itself, nothing is contested, one-sided, material or
    under review. `unchanged` needs the instruction-level proof UNCH/1, which S0 mode does not have."""
    code = 'int fn{i}(int a) {{ int b; b = a + 1; return helper(b); }}'
    matches, table = [], {}
    for i in range(6):
        rva = 0x1000 + i * 0x100
        same = func(f'fn{i}', rva, code=code.format(i=i), callees=('helper',))
        matches.append(match(f'm{i}', 'unchanged', older=[same], newer=[same], types=['ExactBytesFunctionHasher']))
        table[va(rva)] = [[va(rva), ['ExactBytesFunctionHasher']]]
    manifest = run(inputs(matches, raw=raw_ok(table)), tmp_path / 'xvx')
    counts = manifest.counts
    assert counts.decisions.matched == 6 and counts.total() == 6
    assert counts.decisions.contested == counts.decisions.older_only == counts.decisions.newer_only == 0
    assert counts.materiality.material == counts.materiality.review == counts.materiality.unknown == 0
    assert all(not row.change_classes for row in rows_of(tmp_path / 'xvx', manifest))


# --- identity: the result id is known before the run ------------------------------------------------------------------

def test_plan_identity_is_the_result_id_and_independent_of_input_order(tmp_path):
    data = rich_inputs()
    ident = plan_identity(data, addr_map(), ALL_SOURCES)
    manifest = run(shuffled(data, 5), tmp_path / 'r')
    assert manifest.result_id == ident.result_id == plan_identity(shuffled(data, 9), addr_map(), ALL_SOURCES).result_id
    assert manifest.sources == ident.source_refs and manifest.manual_digest == ident.manual_digest
    assert manifest.config_digest == ident.config_digest


def test_each_identity_input_changes_the_result_id():
    data = rich_inputs()
    base = plan_identity(data, addr_map(), ALL_SOURCES).result_id
    no_manual = dataclasses.replace(data, matches=tuple(m for m in data.matches if not m.manual))
    refused = loaded(bindiff_set([bd(0x1000, 0x1080)], older='f' * 64, newer=NEW_SHA, file_sha='9' * 64), 'foreign')

    def raw(status):
        return dataclasses.replace(data, run=dataclasses.replace(data.run, raw=RawGhidriff(status=status,
                                                                                           sha256=RAW_SHA)))
    variants = {
        'raw output': with_raw_sha(data, 'd' * 64),
        'backend version': dataclasses.replace(data, run=dataclasses.replace(data.run, backend_version='2')),
        'one engine set fewer': dataclasses.replace(data, secondary=data.secondary[:1]),
        'a correction fewer': no_manual,
        'another older artifact': dataclasses.replace(data, older_sha256='e' * 64),
        # inputs that are refused change the content (a degrading limitation), so they change the id as well
        'a set for another pair': dataclasses.replace(data, secondary=(*data.secondary, refused)),
        'raw output missing': raw('missing'), 'raw output changed': raw('hash-mismatch'),
        'raw output unparsable': raw('unparsable'),
    }
    ids = {name: plan_identity(item, addr_map(), ALL_SOURCES).result_id for name, item in variants.items()}
    assert base not in ids.values() and len(set(ids.values())) == len(ids), ids


def test_same_id_means_same_content_for_refused_inputs(tmp_path):
    """The store refuses one result id with two contents (`result-drift`); the compute step must never produce it."""
    data = rich_inputs()
    refused = loaded(bindiff_set([bd(0x1000, 0x1080)], older='f' * 64, newer=NEW_SHA, file_sha='9' * 64), 'foreign')
    with_refused = dataclasses.replace(data, secondary=(*data.secondary, refused))
    first, second = run(with_refused, tmp_path / 'a'), run(shuffled(with_refused, 4), tmp_path / 'b')
    assert first.status == 'partial' and 'bindiff-pair-mismatch' in first.limitations
    assert first == second and files_of(tmp_path / 'a') == files_of(tmp_path / 'b')
    assert first.result_id != run(data, tmp_path / 'c').result_id
    assert any(ref.entry_id == 'foreign' for ref in first.sources)  # looked at, listed, refused


def test_the_source_selection_is_part_of_the_identity():
    data = rich_inputs()
    everything = plan_identity(data, addr_map(), ALL_SOURCES)
    only_ghidriff = plan_identity(data, addr_map(), ['ghidriff'])
    assert only_ghidriff.result_id != everything.result_id
    # inputs of a source that is not selected never matter
    stripped = dataclasses.replace(data, secondary=(), matches=tuple(m for m in data.matches if not m.manual))
    assert plan_identity(stripped, addr_map(), ['ghidriff']).result_id == only_ghidriff.result_id


def test_content_limits_are_part_of_the_identity_and_operational_ones_are_not():
    """S0a-FIX (02 s9.1): `limits_digest` covers the limits that can change a result, not timeouts, memory, store or
    display numbers, so a UI or retention setting never invalidates cached results."""
    data = rich_inputs()
    base = plan_identity(data, addr_map(), ALL_SOURCES).result_id

    def with_limit(**change):
        return plan_identity(data, addr_map(), ALL_SOURCES, limits=dataclasses.replace(DEFAULT_LIMITS, **change))
    for name in ('l01_functions_per_side', 'l28_deltas_per_pair', 'l29_pseudo_lines', 'l29_pseudo_chars',
                 'l39_atoms_per_row'):
        assert name in CONTENT_LIMIT_FIELDS  # every limit the S0 compute step reads changes the bytes it writes
        assert with_limit(**{name: getattr(DEFAULT_LIMITS, name) - 1}).result_id != base, name
    for name in ('l33_displayed_rows', 'l32_results_kept', 'l35_filter_ms', 'l37_progress_poll_ms'):
        assert name in OPERATIONAL_LIMIT_FIELDS
        assert with_limit(**{name: getattr(DEFAULT_LIMITS, name) + 1}).result_id == base, name


def test_identity_needs_the_recorded_raw_hash():
    data = rich_inputs()
    no_hash = dataclasses.replace(data, run=dataclasses.replace(data.run, raw=RawGhidriff(status='missing')))
    with pytest.raises(UnifiedError) as caught:
        plan_identity(no_hash, addr_map(), ALL_SOURCES)
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INPUT', 'no-raw-hash')


# --- partial results and cooperative stops -------------------------------------------------------------------------------

@pytest.mark.parametrize('status', ['missing', 'hash-mismatch', 'unparsable'])
def test_unusable_raw_output_gives_a_partial_result_that_says_why(tmp_path, status):
    data = rich_inputs()
    broken = dataclasses.replace(data, run=dataclasses.replace(data.run, raw=RawGhidriff(status=status,
                                                                                         sha256=RAW_SHA)))
    manifest = run(broken, tmp_path / 'p')
    assert manifest.status == 'partial' and f'raw-{status}' in manifest.limitations
    ghidriff = next(s for s in manifest.sources if s.source == 'ghidriff')
    assert ghidriff.file_sha256 is None and ghidriff.version == f'1 [raw-{status}]'  # the file is not used; why is kept
    assert rows_of(tmp_path / 'p', manifest)  # the snapshot still yields rows


def test_a_complete_result_names_the_missing_instruction_level_data(tmp_path):
    manifest = run(rich_inputs(), tmp_path / 'c')
    assert manifest.status == 'complete' and 'ir-not-extracted' in manifest.limitations


def test_compute_stops_on_cancel_and_on_deadline_and_leaves_no_manifest(tmp_path):
    event = threading.Event()
    event.set()
    with pytest.raises(BudgetExhausted) as cancelled:
        run(rich_inputs(), tmp_path / 'c', budget=Budget(cancel=event, check_every=1))
    assert cancelled.value.code == 'PT-UNIFIED-CANCEL'
    with pytest.raises(BudgetExhausted) as late:
        run(rich_inputs(), tmp_path / 'd', budget=Budget(deadline=5.0, clock=lambda: 10.0, check_every=1))
    assert late.value.code == 'PT-UNIFIED-TIMEOUT'
    assert not (tmp_path / 'c' / store.MANIFEST).exists() and not (tmp_path / 'd' / store.MANIFEST).exists()


def test_stage_events_arrive_in_order(tmp_path):
    seen: list[StageEvent] = []
    run(rich_inputs(), tmp_path / 'e', emit=seen.append)
    assert [(e.stage, e.done, e.total) for e in seen] == [('sources', 0, 3), ('fusion', 1, 3), ('facts', 2, 3),
                                                          ('write', 3, 3)]


def test_degrading_limitations_are_only_the_input_losses():
    for slug in ('raw-missing', 'raw-hash-mismatch', 'raw-unparsable', 'bindiff-pair-mismatch',
                 'rz-diff-address-basis-not-comparable', 'ghidriff-address-basis-not-comparable'):
        assert compute.is_degrading(slug)
    for slug in ('ir-not-extracted', 'bindiff-stub-rows-not-identified', 'externals-skipped:3', 'no-address:2',
                 'rz-diff-untested-version:0.8.0'):
        assert not compute.is_degrading(slug)


# --- the exchange files ---------------------------------------------------------------------------------------------

def request_document(tmp_path, **kw):
    path, _ = write_worker_request(tmp_path, rich_inputs(), **kw)
    return json.loads(path.read_text(encoding='utf-8'))


def test_request_model_is_strict(tmp_path):
    document = request_document(tmp_path)
    assert WorkerRequest.model_validate_json(json.dumps(document)).contract == 'unified-worker-request/1'
    bad = {
        'extra field': {**document, 'surprise': 1},
        'upper-case digest': {**document, 'older_sha256': 'A' * 64},
        'unknown source': {**document, 'sources': ['ghidriff', 'nowhere']},
        'no sources': {**document, 'sources': []},
        'zero budget': {**document, 'budget_seconds': 0},
        'empty layout': {**document, 'older_layout': {'image_base': 0, 'size_of_image': 0}},
        'wrong raw state': {**document, 'raw_status': 'unparsable'},
        'wrong contract': {**document, 'contract': 'unified-worker-request/2'},
    }
    for name, doc in bad.items():
        with pytest.raises(ValueError):
            WorkerRequest.model_validate_json(json.dumps(doc))
        assert name


@pytest.mark.parametrize('content', [b'', b'{', b'[]', b'\xff\xfe', b'{"contract": "unified-worker-request/1", "a": 1}',
                                     b'{"a": 1, "a": 2}'], ids=['empty', 'open', 'list', 'binary', 'unknown', 'dup'])
def test_read_request_refuses_malformed_files(tmp_path, content):
    path = tmp_path / 'request.json'
    path.write_bytes(content)
    with pytest.raises(UnifiedError) as caught:
        exchange.read_request(path)
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INPUT', 'request-invalid')


def test_read_request_refuses_a_huge_or_missing_file(tmp_path):
    big = tmp_path / 'big.json'
    big.write_bytes(b' ' * (exchange.EXCHANGE_MAX_BYTES + 1))
    with pytest.raises(UnifiedError) as caught:
        exchange.read_request(big)
    assert caught.value.reason == 'request-too-large'
    with pytest.raises(UnifiedError) as missing:
        exchange.read_request(tmp_path / 'nope.json')
    assert missing.value.reason == 'request-invalid'


@pytest.mark.parametrize('payload', [
    '{"ok":true,"ok":false}',
    '{"ok":false,"reason":"first","reason":"second"}',
    '{"ok":false,"stage_ms":{"calls":1,"calls":2}}',
    '{"ok":false,"rows":NaN}',
    '{"ok":false,"rows":1e999}',
], ids=['duplicate-success', 'duplicate-reason', 'nested-duplicate',
        'nonfinite-constant', 'overflow-float'])
def test_read_worker_report_rejects_noncanonical_json(tmp_path, payload):
    """An invalid report must never be interpreted as worker success."""
    path = tmp_path / 'report.json'
    path.write_text(payload, encoding='utf-8')
    assert exchange.read_report(path) is None


def test_reports_are_read_defensively(tmp_path):
    path = tmp_path / 'report.json'
    assert exchange.read_report(path) is None
    path.write_text('{"ok": true, "surprise": 1}', encoding='utf-8')
    assert exchange.read_report(path) is None
    exchange.write_atomic(path, exchange.WorkerReport(ok=False, error_code='PT-UNIFIED-LIMIT',
                                                      reason='worker-oom').model_dump_json().encode())
    report = exchange.read_report(path)
    assert report is not None and (report.ok, report.error_code, report.reason) == (False, 'PT-UNIFIED-LIMIT',
                                                                                    'worker-oom')
    assert not list(tmp_path.glob('*.part'))  # the atomic write leaves no temporary file


def test_error_messages_are_fixed_templates_and_reasons_are_slugs():
    error = exchange.fail('PT-UNIFIED-INPUT', 'Some Hostile / Reason: <b>x</b> ' + 'y' * 80)
    assert error.message == exchange.MESSAGES['PT-UNIFIED-INPUT']
    assert error.reason and len(error.reason) <= 48 and set(error.reason) <= set('abcdefghijklmnopqrstuvwxyz0123456789-')
    assert exchange.fail('PT-UNIFIED-INPUT', None).reason is None and exchange.slug('  ') is None
    assert set(exchange.MESSAGES) == set(ERROR_CODES)  # every code has a fixed message


# --- running a request ---------------------------------------------------------------------------------------------

def test_a_request_gives_the_same_result_as_the_in_memory_inputs(tmp_path):
    request, data = write_worker_request(tmp_path / 'req', rich_inputs())
    staged = tmp_path / 'staged'
    staged.mkdir()
    report = compute.run_request(request, staged)
    expected = run(data, tmp_path / 'direct')
    assert report.ok and report.status == 'complete' and report.raw_status == 'ok'
    assert report.result_id == expected.result_id and report.rows == expected.counts.total()
    assert report.facts > 0 and report.limitations == expected.limitations
    assert files_of(staged)['rows.jsonl.gz'] == files_of(tmp_path / 'direct')['rows.jsonl.gz']
    progress = json.loads((request.parent / 'progress.json').read_text(encoding='utf-8'))
    assert progress['stage'] == 'write' and set(report.stage_ms) == {'sources', 'fusion', 'facts', 'write'}


def test_a_request_with_a_changed_raw_file_is_a_partial_result_not_an_error(tmp_path):
    request, _ = write_worker_request(tmp_path / 'req', rich_inputs())
    raw = tmp_path / 'req' / 'raw.json'
    raw.write_text(raw.read_text(encoding='utf-8') + ' ', encoding='utf-8')
    staged = tmp_path / 'staged'
    staged.mkdir()
    report = compute.run_request(request, staged)
    assert report.ok and report.status == 'partial' and report.raw_status == 'hash-mismatch'
    assert 'raw-hash-mismatch' in report.limitations


def tamper_snapshot(document, private):
    path = private / 'matches.jsonl'
    path.write_bytes(path.read_bytes().replace(b'read_item', b'read_itex', 1))


def tamper_secondary(document, private):
    path = private / 'secondary-0.json'
    path.write_bytes(path.read_bytes() + b' ')


def tamper_snapshot_path(document, private):
    outside = private.parent / 'outside.jsonl'
    outside.write_bytes((private / 'matches.jsonl').read_bytes())
    document['snapshot']['path'] = str(outside)


def tamper_relative_path(document, private):
    document['snapshot']['path'] = 'matches.jsonl'


def tamper_line_count(document, private):
    document['snapshot_lines'] += 1


def tamper_traversal(document, private):
    document['secondary'][0]['path'] = str(private / '..' / 'raw.json')


@pytest.mark.parametrize('tamper, reason', [
    (tamper_snapshot, 'snapshot-hash-mismatch'), (tamper_secondary, 'secondary-size-mismatch'),
    (tamper_snapshot_path, 'path-outside-private-dir'), (tamper_relative_path, 'path-outside-private-dir'),
    (tamper_line_count, 'snapshot-hash-mismatch'), (tamper_traversal, 'path-outside-private-dir')],
    ids=['snapshot', 'secondary', 'outside', 'relative', 'lines', 'dotdot'])
def test_the_worker_refuses_inputs_that_do_not_match_the_request(tmp_path, tamper, reason):
    request, _ = write_worker_request(tmp_path / 'req', rich_inputs(), tamper=tamper)
    staged = tmp_path / 'staged'
    staged.mkdir()
    with pytest.raises(UnifiedError) as caught:
        compute.run_request(request, staged)
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INPUT', reason)
    assert not list(staged.iterdir())  # nothing is staged for an input that failed its check


# --- the hidden entry -------------------------------------------------------------------------------------------------

def start(tmp_path, tamper=None):
    request, _ = write_worker_request(tmp_path / 'req', rich_inputs(), tamper=tamper)
    staged = tmp_path / 'staged'
    staged.mkdir()
    return request, staged, ['--request', str(request), '--result-dir', str(staged)]


def test_worker_main_succeeds_and_writes_the_report_next_to_the_request(tmp_path):
    request, staged, argv = start(tmp_path)
    assert worker.main(argv) == worker.EXIT_OK
    report = exchange.read_report(request.parent / 'report.json')
    assert report is not None and report.ok and report.result_id
    manifest = store.verify_result_dir(staged, expected_result_id=report.result_id)
    assert manifest.status == 'complete'


@pytest.mark.parametrize('argv', [[], ['--request', 'x'], ['--request', 'x', '--result-dir'], ['--bogus', 'a', 'b', 'c'],
                                  ['--self-check', 'extra']], ids=['none', 'half', 'dangling', 'unknown', 'extra'])
def test_worker_main_rejects_bad_usage(capsys, argv):
    assert worker.main(argv) == worker.EXIT_USAGE
    assert 'usage: unified _worker' in capsys.readouterr().err


def test_worker_main_rejects_an_unusable_request_without_a_traceback(tmp_path, capsys):
    assert worker.main(['--request', str(tmp_path / 'nope.json'), '--result-dir', str(tmp_path)]) == worker.EXIT_USAGE
    err = capsys.readouterr().err
    assert 'unusable request' in err and 'Traceback' not in err


def test_worker_main_reports_a_failed_input_check_as_an_error_document(tmp_path):
    request, staged, argv = start(tmp_path, tamper=tamper_snapshot)
    assert worker.main(argv) == worker.EXIT_ERROR_DOC
    report = exchange.read_report(request.parent / 'report.json')
    assert report is not None and not report.ok
    assert (report.error_code, report.reason) == ('PT-UNIFIED-INPUT', 'snapshot-hash-mismatch')
    assert not list(staged.iterdir())


@pytest.mark.parametrize('error, exit_code, code', [
    (BudgetExhausted('PT-UNIFIED-CANCEL', 'x', reason='cancelled'), worker.EXIT_CANCEL, 'PT-UNIFIED-CANCEL'),
    (BudgetExhausted('PT-UNIFIED-TIMEOUT', 'x', reason='deadline'), worker.EXIT_ERROR_DOC, 'PT-UNIFIED-TIMEOUT'),
    (UnifiedError('PT-UNIFIED-LIMIT', 'x', reason='part-too-large'), worker.EXIT_ERROR_DOC, 'PT-UNIFIED-LIMIT')],
    ids=['cancel', 'deadline', 'limit'])
def test_worker_main_maps_typed_errors_to_exit_codes_and_a_report(tmp_path, monkeypatch, error, exit_code, code):
    request, _, argv = start(tmp_path)

    def boom(*args, **kwargs):
        raise error
    monkeypatch.setattr(compute, 'run_request', boom)
    assert worker.main(argv) == exit_code
    report = exchange.read_report(request.parent / 'report.json')
    assert report is not None and report.error_code == code and report.reason == error.reason


def test_worker_main_uses_the_c3_exit_code_for_memory_errors(tmp_path, monkeypatch):
    request, _, argv = start(tmp_path)

    def boom(*args, **kwargs):
        raise MemoryError
    monkeypatch.setattr(compute, 'run_request', boom)
    assert worker.main(argv) == worker.EXIT_MEMORY == 22
    assert not (request.parent / 'report.json').exists()


def test_worker_main_keeps_unexpected_failures_on_stderr_only(tmp_path, monkeypatch, capsys):
    request, _, argv = start(tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError('a message with a path C:\\secret\\file')
    monkeypatch.setattr(compute, 'run_request', boom)
    assert worker.main(argv) == worker.EXIT_INTERNAL
    assert 'RuntimeError' in capsys.readouterr().err
    assert not (request.parent / 'report.json').exists()  # a message never becomes part of a stored result


def test_a_report_path_outside_the_private_directory_is_not_written(tmp_path):
    outside = tmp_path / 'elsewhere.json'

    def point_outside(document, private):
        document['report_path'] = str(outside)
    _, _, argv = start(tmp_path, tamper=point_outside)
    assert worker.main(argv) == worker.EXIT_OK and not outside.exists()


def test_self_check_imports_the_modules_of_this_slice(capsys):
    assert worker.main(['--self-check']) == worker.EXIT_OK
    assert 'self-check ok' in capsys.readouterr().out
    slice_modules = {'addressing', 'contracts', 'keys', 'limits', 'registry', 'store', 'sources', 'sources.ghidriff',
                     'sources.manual', 'sources.secondary', 'fusion.components', 'fusion.arbiter', 'facts.pseudo',
                     'facts.channels', 'facts.verdict', 'exchange', 'compute', 'pipeline', 'worker', 'cli'}
    assert slice_modules <= set(worker.MODULES)


def test_ladder_cap_hits_make_the_result_partial_except_neighbour_cap_ue_b_06():
    for slug in ('ladder-limit-block-cap:3', 'ladder-limit-assign-time-cap:1', 'ladder-limit-callsite-cap:2',
                 'ladder-limit-rehash-wave-cap:1', 'ladder-limit-assign-bucket-cap:4'):
        assert compute.is_degrading(slug), slug
    assert not compute.is_degrading('ladder-limit-neighbour-cap:3')
