"""SPEC-11 §8: the rz-diff 0.9.1 orientation guard and no-function classification, on retained R2 native output.

The fixture holds verbatim stdout from the pinned tool on repo-owned synthetic PEs (research data, not live
acceptance). The guard never swaps sides: a shape that cannot rule out the reversed branch abstains.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

import pytest
from fake_exe import make_fake_exe

from patchtrace.jobs import ProcessResult
from patchtrace.secondary import rzdiff
from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.registry import EngineJob, RawResult, RzDiffAdapter, build_registry
from patchtrace.secondary.runs import cache_key
from patchtrace.secondary.scheduler import ProjectRef, run_engines

FIXTURE = Path(__file__).parent / 'fixtures' / 'secondary' / 'rzdiff-0.9.1-orientation-r2.json'
DATA = json.loads(FIXTURE.read_text(encoding='utf-8'))
DIAGNOSTICS = {item['id']: item for item in DATA['diagnostics']}
BASE = DATA['provenance']['image_base']
ABSTAIN = ('shift-fwd', 'shift-rev', 'one-vs-two', 'two-vs-one')
ORIENTATION = ('PT-SECONDARY-ORIENTATION', 'rzdiff-orientation-unverified')
GUARD = 'rzdiff-orientation-guard/1'
OLD, NEW = 'a' * 64, 'b' * 64


def rvas(functions) -> set[int]:
    return {rva for _name, rva in functions}


def interpret(item: dict):
    return rzdiff.interpret(item['returncode'], item['stdout'], item['stderr'], '0.9.1', item['input0_sha256'],
                            item['input1_sha256'])


def side(addr: int | None) -> dict | None:
    return None if addr is None else {'addr': addr, 'name': f'fcn.{addr:x}', 'size': 4}


def row(older: int | None, newer: int | None) -> dict:
    return {'similarity': 0.5, 'type': 'PARTIAL', 'original': side(older), 'modified': side(newer)}


def test_fixture_provenance_names_the_research_source():
    provenance = DATA['provenance']
    assert provenance['commit'].startswith('b3ceb8b') and provenance['branch'].startswith('codex/r2-')
    assert provenance['source_sha256'] == '1e0d4e91b12e39899d21c22af1b231e8b0950757fd075585566e2e9e2bc28c49'
    assert 'not live acceptance' in provenance['scope']
    assert sorted(DIAGNOSTICS) == sorted((*ABSTAIN, 'two-vs-two'))


@pytest.mark.parametrize('ident', ('shift-fwd', 'shift-rev'), ids=('fwd', 'rev'))
def test_shift_rows_really_are_reversed_relative_to_argv(ident):
    """The hazard the guard exists for: the pure parser labels input1's helper as the older side."""
    item = DIAGNOSTICS[ident]
    (match,) = rzdiff.parse_output(item['stdout'], '0.9.1', item['input0_sha256'], item['input1_sha256']).matches
    assert match.older_address - BASE in rvas(item['input1_functions']) - rvas(item['input0_functions'])
    assert match.newer_address - BASE in rvas(item['input0_functions']) - rvas(item['input1_functions'])


@pytest.mark.parametrize('ident', ABSTAIN, ids=ABSTAIN)
def test_singleton_shapes_abstain_with_a_fixed_classified_error(ident):
    item = DIAGNOSTICS[ident]
    assert rzdiff.parse_output(item['stdout'], '0.9.1', OLD, NEW).matches  # parse_output stays a pure parser
    with pytest.raises(SecondaryError) as info:
        interpret(item)
    assert (info.value.code, info.value.kind) == ORIENTATION
    assert info.value.message == rzdiff.ORIENTATION_MESSAGE


@pytest.mark.parametrize('ident', ABSTAIN, ids=ABSTAIN)
def test_adapter_parse_abstains(ident, tmp_path):
    item = DIAGNOSTICS[ident]
    job = EngineJob(tmp_path / 'older.bin', tmp_path / 'newer.bin', item['input0_sha256'], item['input1_sha256'],
                    {}, tmp_path, threading.Event(), 60.0)
    capability = Capability(engine='rz-diff', supported=True, version='0.9.1', path='/opt/rz-diff',
                            supports_json=True)
    raw = RawResult(0, item['stdout'].encode('utf-8'), item['stderr'], None, None)
    with pytest.raises(SecondaryError) as info:
        RzDiffAdapter().parse(raw, capability, job)
    assert (info.value.code, info.value.kind) == ORIENTATION


def test_two_vs_two_is_accepted_in_argv_order():
    item = DIAGNOSTICS['two-vs-two']
    result = interpret(item)
    assert len(result.matches) == 2 and len({m.newer_address for m in result.matches}) == 2
    for match in result.matches:
        assert match.older_address - BASE in rvas(item['input0_functions'])
        assert match.newer_address - BASE in rvas(item['input1_functions'])
        assert match.older_name == match.newer_name


@pytest.mark.parametrize('rows, accepted', [
    ([row(1, 2)], False),
    ([row(1, None)], False),
    ([row(None, 2)], False),
    ([row(1, 2), row(3, 2)], False),
    ([row(1, 2), row(3, None), row(None, 2)], False),
    ([row(1, 2), row(3, 4)], True),
    ([row(None, 2), row(None, 4)], True),
], ids=['one', 'old-only', 'new-only', 'many-to-one', 'one-newer', 'two-newer', 'two-added'])
def test_rule_counts_distinct_non_null_newer_addresses(rows, accepted):
    text = json.dumps(rows)
    if accepted:
        assert len(rzdiff.interpret(0, text, '', '0.9.1', OLD, NEW).matches) == len(rows)
        return
    with pytest.raises(SecondaryError) as info:
        rzdiff.interpret(0, text, '', '0.9.1', OLD, NEW)
    assert (info.value.code, info.value.kind) == ORIENTATION


def test_empty_array_stays_a_clean_zero_match_result():
    result = rzdiff.interpret(0, '[]\n', '', '0.9.1', OLD, NEW)
    assert result.matches == () and result.engine == 'rz-diff'


def test_run_rzdiff_abstains_and_the_message_holds_no_path(tmp_path):
    folder = tmp_path / 'private-case-folder'
    folder.mkdir()
    older, newer = folder / 'older-secret.sys', folder / 'newer-secret.sys'
    older.write_bytes(b'MZ1')
    newer.write_bytes(b'MZ2')
    capability = Capability(engine='rz-diff', supported=True, version='0.9.1', path=str(folder / 'rz-diff'),
                            supports_json=True)

    def runner(argv, **kwargs):
        return ProcessResult(0, DIAGNOSTICS['shift-fwd']['stdout'], None, stderr_tail='')

    with pytest.raises(SecondaryError) as info:
        rzdiff.run_rzdiff(capability, older, newer, OLD, NEW, env={}, cancel=threading.Event(), runner=runner)
    assert (info.value.code, info.value.kind) == ORIENTATION
    assert 'private-case-folder' not in str(info.value) and 'secret' not in str(info.value)
    assert '/' not in info.value.message and '\\' not in info.value.message


@pytest.mark.parametrize('index, side', [(0, 'older'), (1, 'newer')], ids=['file0', 'file1'])
def test_exit_zero_no_functions_is_classified_per_side(index, side):
    sample = DATA['no_functions'][index]
    assert f'file{index}' in sample['stderr'] and sample['stdout'] == '' and sample['returncode'] == 0
    with pytest.raises(SecondaryError) as info:
        rzdiff.interpret(sample['returncode'], sample['stdout'], sample['stderr'], '0.9.1', OLD, NEW)
    assert (info.value.code, info.value.kind) == ('PT-SECONDARY-INPUT', f'rzdiff-no-functions-{side}')
    assert side in info.value.message and 'file' not in info.value.message


def test_empty_output_without_the_marker_keeps_the_generic_error():
    with pytest.raises(SecondaryError, match='no output') as info:
        rzdiff.interpret(0, '', 'WARNING: something else\n', '0.9.1', OLD, NEW)
    assert info.value.kind is None


def test_nonzero_exit_with_the_marker_stays_a_run_error():
    with pytest.raises(SecondaryError) as info:
        rzdiff.interpret(1, '', 'ERROR: rz-diff: No functions found in file0.\n', '0.9.1', OLD, NEW)
    assert info.value.code == 'PT-SECONDARY-RUN' and info.value.kind is None


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def project(tmp_path) -> ProjectRef:
    older, newer = tmp_path / 'older.sys', tmp_path / 'newer.sys'
    older.write_bytes(b'older-artifact')
    newer.write_bytes(b'newer-artifact')
    return ProjectRef(older, newer, sha(older), sha(newer))


def fake_rz(tmp_path, stdout: str, stderr: str = '') -> str:
    source = ("import sys\n"
              "if sys.argv[1:] == ['-v']:\n    print('rz-diff 0.9.1')\n    sys.exit(0)\n"
              f"sys.stderr.write({stderr!r})\nsys.stdout.write({stdout!r})\n")
    return str(make_fake_exe(tmp_path / 'bin', 'rz-diff', source))


@pytest.mark.parametrize('stdout, stderr, code, kind', [
    (DIAGNOSTICS['shift-fwd']['stdout'], '', 'PT-SECONDARY-ORIENTATION', 'rzdiff-orientation-unverified'),
    ('', DATA['no_functions'][0]['stderr'], 'PT-SECONDARY-INPUT', 'rzdiff-no-functions-older'),
], ids=['one-row', 'no-functions'])
def test_run_engines_records_a_failed_run_with_its_kind(tmp_path, stdout, stderr, code, kind):
    (outcome,) = run_engines(project(tmp_path), ['rz-diff'], cancel=threading.Event(), env=dict(os.environ),
                             registry=build_registry(rz_diff=fake_rz(tmp_path, stdout, stderr)))
    assert outcome.run.status == 'failed' and outcome.run.error_code == code
    assert outcome.run.provenance == {'failure_kind': kind}
    assert outcome.match_set is None and outcome.run.match_set_id is None and outcome.error.kind == kind


class RecordingCache:
    def __init__(self):
        self.keys: list[str] = []

    def find(self, key: str):
        self.keys.append(key)
        return None


def test_cache_key_carries_the_guard_so_pre_guard_sets_are_not_reused(tmp_path):
    ref, cache = project(tmp_path), RecordingCache()
    exe = fake_rz(tmp_path, DIAGNOSTICS['two-vs-two']['stdout'])
    (outcome,) = run_engines(ref, ['rz-diff'], cancel=threading.Event(), env=dict(os.environ), cache=cache,
                             registry=build_registry(rz_diff=exe))
    assert outcome.run.status == 'ok' and len(outcome.match_set.matches) == 2
    pre_guard = cache_key('rz-diff', '0.9.1', outcome.run.argv_digest, ref.older_sha256, ref.newer_sha256)
    guarded = cache_key('rz-diff', '0.9.1', outcome.run.argv_digest, ref.older_sha256, ref.newer_sha256,
                        extra=(GUARD,))
    assert cache.keys == [outcome.run.cache_key] == [guarded] and guarded != pre_guard
    assert outcome.run.provenance == {}


def test_cache_extra_is_the_guard_identity(tmp_path):
    capability = Capability(engine='rz-diff', supported=True, version='0.9.1', path='/opt/rz-diff',
                            supports_json=True)
    job = EngineJob(tmp_path / 'o', tmp_path / 'n', OLD, NEW, {}, tmp_path, threading.Event(), 60.0)
    assert RzDiffAdapter().cache_extra(capability, job) == (GUARD,)
