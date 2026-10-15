"""LBL-11c engine adapters: attention (the shipped lead list) and BinDiff from supplied files. Every engine output here is
SYNTHETIC (hand-built Ghidriff JSON, fake BinDiff steps): it checks the mapping and the BLOCKED/failed rules, never live
engine evidence."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

from bindiff_builder import build
from test_tier_r_eval_metrics import FUNCS, make_labels

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from patchtrace.secondary.bindiff import import_bindiff  # noqa: E402
from patchtrace.secondary.contracts import Capability, SecondaryError  # noqa: E402
from tools.calibration.evalcore.engines import attention  # noqa: E402
from tools.calibration.evalcore.engines import bindiff as BD  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import evaluate as E  # noqa: E402

BASE = 0x180000000
LABELS = make_labels(FUNCS, pair_id='syn-att')
OLD_CODE = 'int f(char *b, int n, int i) {\n  return b[i];\n}'
NEW_CODE = 'int f(char *b, int n, int i) {\n  if (i >= n) {\n    return -1;\n  }\n  return b[i];\n}'


def _fn(name, rva, code):
    return {'name': name, 'fullname': name, 'address': f'{BASE + rva:x}', 'code': code}


def _ghidriff(labels=LABELS):
    """C gains a bounds guard; D is listed modified but its decompiled text is unchanged (no signal)."""
    mod = [{'old': _fn('C', 0x1020, OLD_CODE), 'new': _fn('C', 0x1020, NEW_CODE), 'ratio': 0.75,
            'match_types': ['ExactBytes'], 'diff_type': ['code']},
           {'old': _fn('D', 0x1030, OLD_CODE), 'new': _fn('D', 0x1030, OLD_CODE), 'ratio': 0.99,
            'match_types': ['ExactBytes'], 'diff_type': ['code']}]
    return {'old_meta': {'Executable SHA256': labels.older.sha256}, 'new_meta': {'Executable SHA256': labels.newer.sha256},
            'functions': {'added': [_fn('H', 0x1070, None)], 'deleted': [_fn('G', 0x1060, None)], 'modified': mod}}


def _place(tmp_path, raw=None):
    (tmp_path / 'syn-att.ghidriff.json').write_text(json.dumps(raw or _ghidriff()), encoding='utf-8')
    return tmp_path


# ---- attention -------------------------------------------------------------------------------------------

def test_attention_flags_only_pairings_with_a_change_signal_in_rank_order(tmp_path):
    out = attention.AttentionProvider(_place(tmp_path))(LABELS, 'hidden')
    assert out.status == 'ok' and out.version == 'attention/1' and out.implicit_unchanged
    rows = {(p.old_rva, p.new_rva): p for p in out.predictions}
    assert (rows[(0x1020, 0x1020)].changed, rows[(0x1020, 0x1020)].order_key) == (True, (1,))
    assert not rows[(0x1030, 0x1030)].changed and len(rows) == 2   # a zero-score rank is not a lead
    assert (out.old_only, out.new_only) == (frozenset({0x1060}), frozenset({0x1070}))


def test_attention_scores_through_the_report_without_pooling_with_ghidriff(tmp_path):
    imports = _place(tmp_path)
    doc = E.evaluate([LABELS], [E.GhidriffImportProvider(imports), attention.AttentionProvider(imports)], b_count=20)
    cells = doc['labels']['authored']
    # Ghidriff flags both modified pairs; the lead list flags only the one with a change signal
    assert (cells['ghidriff']['changed']['paired_correct'], cells['ghidriff']['changed']['flagged']) == (2, 2)
    assert (cells['attention']['changed']['paired_correct'], cells['attention']['changed']['flagged']) == (2, 1)
    assert cells['attention']['unchanged']['flagged'] == 0
    assert [e['engine'] for e in doc['engines']] == ['ghidriff', 'attention']
    assert C.load_report(C.dump_json(doc)).report_sha256 == doc['report_sha256']


def test_attention_output_digest_changes_with_the_order(tmp_path):
    out = attention.AttentionProvider(_place(tmp_path))(LABELS, 'hidden')
    other = E.EngineOutput(out.engine, out.status, out.version, predictions=tuple(
        E.Prediction(p.old_rva, p.new_rva, p.changed, p.similarity_milli, p.old_name, p.new_name,
                     order_key=None if p.order_key is None else (9,)) for p in out.predictions),
        old_only=out.old_only, new_only=out.new_only, implicit_unchanged=True)
    a, b = (E.engine_output_doc(o, LABELS, 'hidden') for o in (out, other))
    assert a != b


def test_attention_blocked_without_import_and_failed_on_wrong_image(tmp_path):
    blocked = attention.AttentionProvider(tmp_path)(LABELS, 'hidden')
    assert blocked.status == 'blocked' and 'decompiled code' in blocked.reason
    assert attention.AttentionProvider(None)(LABELS, 'hidden').status == 'blocked'
    bad = _ghidriff()
    bad['old_meta']['Executable SHA256'] = 'f' * 64
    failed = attention.AttentionProvider(_place(tmp_path, bad))(LABELS, 'hidden')
    assert failed.status == 'failed' and 'does not match' in failed.reason


def test_default_providers_include_attention_and_bindiff_provider(tmp_path):
    names = {p.engine: type(p).__name__ for p in E.default_providers(tmp_path / 'store', tmp_path)}
    assert names == {'rz-diff': 'RzDiffProvider', 'bindiff': 'BindiffProvider', 'ghidriff': 'GhidriffImportProvider',
                     'attention': 'AttentionProvider'}


# ---- bindiff from supplied files -------------------------------------------------------------------------

ROWS = [(1, BASE + 0x1000, 'a', BASE + 0x1000, 'a', 1.0, 1.0, 0, 7),
        (2, BASE + 0x1020, 'c', BASE + 0x1020, 'c', 0.5, 0.9, 0, 7)]


def _exports(tmp_path):
    for side in ('older', 'newer'):
        (tmp_path / f'syn-att.{side}.BinExport').write_bytes(b'synthetic placeholder, accepted by a fake')
    return tmp_path


class _Steps:
    """Fake probe / accept / run: the supervised steps are exercised against real ones only on a BinDiff machine."""

    def __init__(self, tmp_path, *, supported=True, accept_error=None):
        self.tmp, self.supported, self.accept_error, self.calls = tmp_path, supported, accept_error, []

    def probe(self, executable, cancel=None):
        self.calls.append(('probe', executable))
        return Capability(engine='bindiff', supported=self.supported, version='BinDiff 8', path=str(executable),
                          supports_json=False, reason=None if self.supported else 'synthetic: unsupported build')

    def accept(self, path, *, artifact_sha256, role, private_dir, cancel):
        self.calls.append(('accept', role))
        if self.accept_error:
            raise self.accept_error
        return SimpleNamespace(snapshot_path=path, summary=SimpleNamespace(
            executable_id=artifact_sha256, file_sha256=('1' if role == 'older' else '2') * 64, architecture_name='x86'))

    def run(self, cap, pair, raw_dir, older_sha256, newer_sha256, *, cancel, timeout_seconds):
        self.calls.append(('run', pair.older.file_sha256 < pair.newer.file_sha256))
        target = self.tmp / 'made.BinDiff'
        build(target, hashes=(older_sha256, newer_sha256), functions=ROWS)
        return SimpleNamespace(match_set=import_bindiff(target, older_sha256, newer_sha256))


def _provider(tmp_path, steps, **kwargs):
    return BD.BindiffProvider(tmp_path, probe_fn=steps.probe, accept_fn=steps.accept, run_fn=steps.run, environ={},
                              **kwargs)


def test_bindiff_blocked_without_import_or_export_pair(tmp_path):
    out = _provider(tmp_path, _Steps(tmp_path), executable='/x/bindiff')(LABELS, 'hidden')
    assert out.status == 'blocked' and 'BinExport' in out.reason
    (tmp_path / 'syn-att.older.BinExport').write_bytes(b'x')   # one side only is still no pair
    assert _provider(tmp_path, _Steps(tmp_path), executable='/x/bindiff')(LABELS, 'hidden').status == 'blocked'


def test_bindiff_export_pair_without_executable_is_blocked_and_never_searched(tmp_path):
    steps = _Steps(tmp_path)
    out = _provider(_exports(tmp_path), steps)(LABELS, 'hidden')
    assert out.status == 'blocked' and 'PATCHTRACE_BINDIFF' in out.reason and steps.calls == []


def test_bindiff_executable_comes_from_the_environment_variable(tmp_path):
    steps = _Steps(tmp_path)
    provider = BD.BindiffProvider(_exports(tmp_path), environ={BD.ENV_VAR: '/opt/bd/bindiff'}, probe_fn=steps.probe,
                                  accept_fn=steps.accept, run_fn=steps.run)
    assert provider(LABELS, 'hidden').status == 'ok' and steps.calls[0] == ('probe', '/opt/bd/bindiff')


def test_bindiff_unsupported_build_is_blocked_with_its_reason(tmp_path):
    out = _provider(_exports(tmp_path), _Steps(tmp_path, supported=False), executable='/x/bindiff')(LABELS, 'hidden')
    assert out.status == 'blocked' and 'unsupported build' in out.reason


def test_bindiff_export_pair_is_diffed_and_mapped(tmp_path):
    steps = _Steps(tmp_path)
    out = _provider(_exports(tmp_path), steps, executable='/x/bindiff')(LABELS, 'hidden')
    assert out.status == 'ok'
    assert [(p.old_rva, p.changed) for p in out.predictions] == [(0x1000, False), (0x1020, True)]
    assert [c[0] for c in steps.calls] == ['probe', 'accept', 'accept', 'run']


def test_bindiff_rejected_export_is_failed_not_zero(tmp_path):
    error = SecondaryError('PT-SECONDARY-INPUT', 'The older .BinExport is not a BinExport2 file.')
    out = _provider(_exports(tmp_path), _Steps(tmp_path, accept_error=error), executable='/x/bindiff')(LABELS, 'hidden')
    assert out.status == 'failed' and 'not a BinExport2' in out.reason


def test_bindiff_imported_file_wins_over_the_export_pair(tmp_path):
    steps = _Steps(tmp_path)
    build(tmp_path / 'syn-att.BinDiff', hashes=(LABELS.older.sha256, LABELS.newer.sha256), functions=ROWS[:1])
    out = _provider(_exports(tmp_path), steps, executable='/x/bindiff')(LABELS, 'hidden')
    assert out.status == 'ok' and len(out.predictions) == 1 and steps.calls == []


def test_bindiff_reversed_exports_are_refused_by_the_binder(tmp_path):
    steps = _Steps(tmp_path)
    plain = steps.accept

    def swapped(path, *, artifact_sha256, role, private_dir, cancel):
        other = LABELS.newer.sha256 if role == 'older' else LABELS.older.sha256
        return plain(path, artifact_sha256=other, role=role, private_dir=private_dir, cancel=cancel)

    provider = BD.BindiffProvider(_exports(tmp_path), executable='/x/bindiff', environ={}, probe_fn=steps.probe,
                                  accept_fn=swapped, run_fn=steps.run)
    out = provider(LABELS, 'hidden')
    assert out.status == 'failed' and 'swapped' in out.reason and not [c for c in steps.calls if c[0] == 'run']
