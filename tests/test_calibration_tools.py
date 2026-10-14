"""Dev tooling (calibration-corpus-and-model.md §3, §4, §5, §9.7, §10.4): contracts, the no-Microsoft-binaries
guard, corpus verify/fetch, lineage + roles, sampling, blind labelling, agreement, reports, the single-use
locked-test runner, schemas and train/serve feature identity. Synthetic data only."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from patchtrace.calibration.artifact import canonical_json, parse_artifact  # noqa: E402
from patchtrace.calibration.features import FEATURES, ExtractionContext, extract, feature_names  # noqa: E402
from patchtrace.calibration.predict import predict  # noqa: E402
from patchtrace.models import FunctionMatch, FunctionRecord  # noqa: E402
from patchtrace.secondary.contracts import SecondaryMatch, SecondaryMatchSet  # noqa: E402
from patchtrace.secondary.reconcile import reconcile  # noqa: E402
from tools.calibration import corpus  # noqa: E402
from tools.calibration.agree import agreement_report, cohen_kappa, kappa_ci, raw_agreement  # noqa: E402
from tools.calibration.common import Row, det_uniform  # noqa: E402
from tools.calibration.contracts import ContractError, load_labels, load_manifest  # noqa: E402
from tools.calibration.cv import FittedModel, fit_base, fit_calibrator  # noqa: E402
from tools.calibration.fit import build_artifact, impute, medians  # noqa: E402
from tools.calibration.label import AnnotationLog, ChainError, blind_view, consolidate, run_terminal  # noqa: E402
from tools.calibration.lineage import BinaryInfo, assign_roles, cluster, role_u  # noqa: E402
from tools.calibration.mathcore import logit_score, standardise_apply  # noqa: E402
from tools.calibration.ood_fit import ood_fit  # noqa: E402
from tools.calibration.report import make_report, render_markdown, verify_report  # noqa: E402
from tools.calibration.run_locked_test import LockedTestError, run_locked_test  # noqa: E402
from tools.calibration.sample import Candidate, sample, sample_digest  # noqa: E402
from tools.calibration.schemas import render  # noqa: E402

H = {k: hashlib.sha256(k.encode()).hexdigest() for k in ('w1', 'w2', 'r1', 'tool', 'env', 'ev')}


def manifest(**over):
    doc = {'contract': 'calibration-corpus/1', 'corpus_id': 'c-test', 'created': '2026-10-14', 'tool_git': 'abc',
           'binaries': [
               {'id': 'b001', 'tier': 'W', 'file_name': 'ntdll.dll', 'arch': 'x64', 'sha256': H['w1'], 'size': 2,
                'winbindex': {'timestamp': 1, 'virtual_size': 4096, 'version': '10.0.1', 'kb': ['KB1']},
                'pdb': {'guid_age': None, 'name': 'ntdll.pdb', 'used_for': 'labels-only'}, 'toolchain': 'msvc',
                'redistribution': 'none'},
               {'id': 'b002', 'tier': 'W', 'file_name': 'ntdll.dll', 'arch': 'x64', 'sha256': H['w2'], 'size': 2,
                'winbindex': {'timestamp': 2, 'virtual_size': 4096}, 'redistribution': 'none'},
               {'id': 'b101', 'tier': 'R', 'file_name': 'zlib1.dll', 'arch': 'x64', 'sha256': H['r1'],
                'source': {'git': 'https://example.invalid/zlib', 'commit': 'abcdef1', 'license': 'Zlib'},
                'recipe': {'toolchain_digest': H['tool'], 'argv': ['clang-cl', '/O2'], 'opt': 'O2', 'strip': True,
                           'env_digest': H['env']}, 'redistribution': 'Zlib'}],
           'pairs': [{'id': 'p001', 'older': 'b001', 'newer': 'b002', 'kind': 'adjacent-patch', 'lineage': 'L-ntdll',
                      'family_tags': ['usermode-dll']}],
           'lineages': [{'id': 'L-ntdll', 'members': ['b001', 'b002'], 'cluster_rule': 'file-name',
                         'cluster_evidence_sha256': H['ev']},
                        {'id': 'L-zlib', 'members': ['b101'], 'cluster_rule': 'project',
                         'cluster_evidence_sha256': H['ev']}],
           'split': {'salt': 'c9-v1', 'method': 'sha256'}}
    doc.update(over)
    return doc


def enc(doc) -> bytes:
    return json.dumps(doc).encode()


# ---- contracts ---------------------------------------------------------------------------------------------

def test_manifest_valid_and_negative_cases():
    m = load_manifest(enc(manifest()))
    assert [b.id for b in m.binaries] == ['b001', 'b002', 'b101']
    bad_cases = [
        enc(manifest()).replace(b'"corpus_id": "c-test"', b'"corpus_id": "c-test", "corpus_id": "x"'),
        enc(manifest()).replace(b'"size": 2', b'"size": NaN', 1),
        enc(manifest(extra=1)),
        enc(manifest(binaries=[dict(manifest()['binaries'][0], winbindex=None)] + manifest()['binaries'][1:])),
        enc(manifest(binaries=[dict(manifest()['binaries'][0], redistribution='MIT')] + manifest()['binaries'][1:])),
        enc(manifest(binaries=manifest()['binaries'][:2] + [dict(manifest()['binaries'][2], recipe=None)])),
        enc(manifest(lineages=manifest()['lineages'][:1])),
        enc(manifest(pairs=[dict(manifest()['pairs'][0], lineage='L-zlib')])),
        enc(manifest(binaries=[dict(manifest()['binaries'][0], file_name='../ntdll.dll')]
                     + manifest()['binaries'][1:])),
        b'[]',
    ]
    for data in bad_cases:
        with pytest.raises(ContractError):
            load_manifest(data)


def label_line(**over):
    rec = {'pair': 'p001', 'match_id': 'm1', 'older': {'rva': 4096, 'size': 10, 'body_sha256': H['w1']},
           'newer': {'rva': 4096, 'size': 12, 'body_sha256': H['w2']}, 'A': 'same', 'subtype': None,
           'B': None, 'C': None, 'D': None, 'source': 'synthetic-exact', 'annotators': [], 'adjudicated': False,
           'guideline': 'g1', 'sampling': {'stratum': 'natural', 'stage': 'S1', 'p_incl': 1.0}, 'notes': ''}
    rec.update(over)
    return json.dumps(rec).encode()


def test_label_records_strict():
    recs = load_labels(label_line() + b'\n' + label_line(match_id='m2', A='no-counterpart', subtype='N7') + b'\n')
    assert [r.y for r in recs] == [1, 0]
    assert load_labels(label_line(A='indeterminate'))[0].y is None
    for bad in (label_line(B='x'), label_line(A='maybe'), label_line(subtype='N13'),
                label_line(sampling={'stratum': 'natural', 'stage': 'S1', 'p_incl': 0}),
                label_line() + b'\n' + label_line(), label_line().replace(b'"notes": ""', b'"notes": "", "x": 1'),
                label_line().replace(b'"size": 10', b'"size": 10, "size": 11')):
        with pytest.raises(ContractError):
            load_labels(bad)


# ---- guard / verify / fetch ---------------------------------------------------------------------------------

def pe_bytes() -> bytes:
    head = bytearray(b'MZ' + b'\0' * 0x3E)
    struct.pack_into('<I', head, 0x3C, 0x40)
    return bytes(head) + b'PE\0\0' + b'\0' * 64


def test_executable_magic():
    assert corpus.executable_magic(pe_bytes()) == 'pe'
    assert corpus.executable_magic(b'\x7fELF\x02') == 'elf'
    assert corpus.executable_magic(b'MZ') is None and corpus.executable_magic(b'hello world' * 10) is None


def test_guard_blocks_pe_outside_fixtures_and_tier_w_hash(tmp_path, monkeypatch):
    monkeypatch.setenv(corpus.ROOT_ENV, str(tmp_path / 'outside'))
    tree = tmp_path / 'tree'
    (tree / 'docs').mkdir(parents=True)
    (tree / 'tests' / 'fixtures').mkdir(parents=True)
    (tree / 'docs' / 'evil.bin').write_bytes(pe_bytes())
    (tree / 'tests' / 'fixtures' / 'ok.exe').write_bytes(pe_bytes())
    (tree / 'notes.txt').write_bytes(b'ab')  # sha256('ab') used as a fake Tier-W hash below
    m = load_manifest(enc(manifest(binaries=[dict(manifest()['binaries'][0], sha256=hashlib.sha256(b'ab')
                                                                                  .hexdigest())]
                                   + manifest()['binaries'][1:])))
    problems = corpus.guard(tree, m, files=['docs/evil.bin', 'tests/fixtures/ok.exe', 'notes.txt'])
    assert any('docs/evil.bin' in p and 'PE' in p for p in problems)
    assert not any('ok.exe' in p for p in problems)
    assert any('notes.txt' in p and 'Tier-W' in p for p in problems)
    monkeypatch.setenv(corpus.ROOT_ENV, str(tree / 'calib'))
    assert any('inside the work tree' in p for p in corpus.guard(tree, None, files=[]))


def test_repository_contains_no_executable_images_outside_fixtures():
    """CI guard: Microsoft (or any) PE/ELF images never enter git outside the fixture allow-list."""
    tracked = corpus.candidate_files(ROOT, include_untracked=False)
    assert 'pyproject.toml' in tracked
    problems = [p for p in corpus.guard(ROOT, None, files=tracked) if 'inside the work tree' not in p]
    assert problems == []


def test_verify_detects_tampering_and_missing(tmp_path):
    m = load_manifest(enc(manifest(binaries=[dict(b, sha256=hashlib.sha256(b'ok').hexdigest(), size=2)
                                             if b['id'] == 'b001' else b for b in manifest()['binaries']])))
    b001 = next(b for b in m.binaries if b.id == 'b001')
    path = corpus.binary_path(tmp_path, b001)
    path.parent.mkdir(parents=True)
    path.write_bytes(b'ok')
    out = corpus.verify(m, tmp_path)
    assert out['ok'] == ['b001'] and out['missing'] == ['b002', 'b101'] and not out['mismatch']
    path.write_bytes(b'no')
    assert corpus.verify(m, tmp_path)['mismatch'] == ['b001']
    assert corpus.verify(m, tmp_path, worktree=tmp_path.parent)['errors']


def test_fetch_stores_only_hash_verified_bytes_and_never_executes(tmp_path):
    data = {'ok': b'ok-bytes'}
    m = load_manifest(enc(manifest(binaries=[dict(manifest()['binaries'][0], sha256=hashlib.sha256(b'ok-bytes')
                                                  .hexdigest(), size=8)] + manifest()['binaries'][1:])))
    plan = corpus.fetch_plan(m)
    assert [p['id'] for p in plan] == ['b001', 'b002']  # Tier W only
    assert plan[0]['url'].endswith('/ntdll.dll/000000011000/ntdll.dll')
    calls = []

    def download(url):
        calls.append(url)
        if '000000021000' in url:
            return b'wrong'
        return data['ok']
    out = corpus.fetch(m, tmp_path, download)
    assert out['stored'] == ['b001'] and out['failed'] == ['b002: hash mismatch (not stored)']
    assert not corpus.binary_path(tmp_path, m.binaries[1]).exists()
    assert corpus.fetch(m, tmp_path, download)['present'] == ['b001']


def test_corpus_cli_init_and_guard(tmp_path, capsys, monkeypatch):
    assert corpus.main(['init', 'c1', '--created', '2026-10-14']) == 0
    doc = json.loads(capsys.readouterr().out)
    doc['lineages'] = []
    load_manifest(enc(doc))
    monkeypatch.setenv(corpus.ROOT_ENV, str(tmp_path / 'calib-outside'))
    (tmp_path / 'tree').mkdir()
    assert corpus.main(['guard', '--worktree', str(tmp_path / 'tree')]) == 0


# ---- lineage and roles ---------------------------------------------------------------------------------------

def test_lineage_union_find_rules_and_threshold_escalation():
    crt = frozenset(f'crt{i}' for i in range(20))
    bins = [BinaryInfo('a1', 'ntdll.dll', body_hashes=crt | {'a'}), BinaryInfo('a2', 'NTDLL.dll'),
            BinaryInfo('b1', 'kernel32.dll', pdb_name='k32.pdb', body_hashes=crt | {'b'}),
            BinaryInfo('b2', 'kernelbase.dll', pdb_name='K32.pdb'),
            BinaryInfo('c1', 'zlib1.dll', project='zlib'), BinaryInfo('c2', 'zlibwapi.dll', project='zlib')]
    res = cluster(bins)
    # CRT overlap would merge a* and b* at 15 %/30 %/50 %: shared code collapses (never split by hand)
    assert sorted(res.lineages.values()) == [('a1', 'a2', 'b1', 'b2'), ('c1', 'c2')]
    res2 = cluster(bins[:2] + bins[2:4])
    assert res2.threshold == 0.5 and len(res2.lineages) == 1  # escalated, still one component: recorded
    assert cluster(bins) == cluster(list(reversed(bins)))
    small_overlap = [BinaryInfo('x', 'x.dll', body_hashes=frozenset({'1', '2', '3', '4'})),
                     BinaryInfo('y', 'y.dll', body_hashes=frozenset({'1', '9', '8', '7'})),
                     BinaryInfo('z', 'z.dll')]
    assert len(cluster(small_overlap).lineages) == 2  # 25 % overlap >= 15 %: x+y joined


def test_roles_are_per_lineage_deterministic_and_respect_shift_declaration():
    ids = [f'L-{i:03d}' for i in range(200)]
    roles = assign_roles(ids, 'c9-v1')
    assert roles == assign_roles(list(reversed(ids)), 'c9-v1')
    share = {r: sum(v == r for v in roles.values()) / 200 for r in ('dev', 'locked-test', 'shift-test')}
    assert 0.5 < share['dev'] < 0.7 and 0.15 < share['locked-test'] < 0.35
    forced = assign_roles(ids, 'c9-v1', shift_test=['L-000'])
    assert forced['L-000'] == 'shift-test'
    assert 0 <= role_u('L-1', 's') < 1
    # pairs inherit their lineage's role, so no lineage is ever split across roles
    pairs = [(f'p{i}', ids[i % 50]) for i in range(500)]
    by_lineage = {}
    for _, lin in pairs:
        by_lineage.setdefault(lin, set()).add(roles[lin])
    assert all(len(v) == 1 for v in by_lineage.values())


# ---- sampling ------------------------------------------------------------------------------------------------

def test_stratified_sampling_inclusion_probabilities_and_determinism():
    cands = [Candidate('p1', f'm{i:04d}', 'SymbolsHash' if i % 3 else 'StructuralGraphHash',
                       det_uniform('r', i), 10 + i) for i in range(1000)]
    cands += [Candidate('p2', f'm{i}', 'X', None, None) for i in range(50)]
    items = sample(cands, budget_per_pair=200, seed=5)
    p1 = [it for it in items if it['pair'] == 'p1']
    assert 150 <= len(p1) <= 260 and all(0 < it['p_incl'] <= 1 for it in p1)
    assert math.fsum(1 / it['p_incl'] for it in p1) == pytest.approx(1000, rel=0.02)  # HT total
    assert all(it['p_incl'] == 1.0 for it in items if it['pair'] == 'p2')  # small pair fully enumerated
    assert sample_digest(items) == sample_digest(sample(list(reversed(cands)), budget_per_pair=200, seed=5))
    with pytest.raises(ValueError):
        sample(cands + cands[:1], budget_per_pair=200, seed=5)


# ---- labelling and agreement ------------------------------------------------------------------------------------

def test_blind_view_hides_engine_output_and_names():
    item = {'pair': 'p', 'match_id': 'm', 'older': {'name': 'NtFoo', 'asm': 'mov', 'ratio': 0.9},
            'engines': [{'similarity_milli': 900, 'verdict': 'corroborated', 'Confidence': 1}], 'Quality': 'x'}
    view = blind_view(item)
    text = json.dumps(view)
    for hidden in ('NtFoo', '0.9', '900', 'corroborated', 'Confidence', 'Quality'):
        assert hidden not in text
    assert view['older']['asm'] == 'mov'
    assert blind_view(item, reveal_names=True)['older']['name'] == 'NtFoo'


def test_annotation_log_chain_and_tamper_detection(tmp_path):
    log = AnnotationLog(tmp_path / 'a.jsonl')
    log.append(pair='p', match_id='m1', annotator='a1', phase='blind', A='same')
    log.append(pair='p', match_id='m2', annotator='a1', phase='blind', A='different')
    assert [e['seq'] for e in log.events()] == [1, 2]
    raw = (tmp_path / 'a.jsonl').read_bytes()
    (tmp_path / 'a.jsonl').write_bytes(raw.replace(b'"different"', b'"same"'))
    with pytest.raises(ChainError):
        log.events()
    lines = raw.splitlines()
    (tmp_path / 'a.jsonl').write_bytes(lines[1] + b'\n')  # deleting the first line breaks the chain
    with pytest.raises(ChainError):
        log.events()


def test_terminal_mode_records_blind_labels_and_resumes(tmp_path):
    log = AnnotationLog(tmp_path / 'b.jsonl')
    items = [{'pair': 'p', 'match_id': f'm{i}', 'older': {'ratio': 0.5, 'bytes': 'aa'}} for i in range(3)]
    answers = iter(['x', 's', '', 'd', 'n4', 'q'])
    shown = []
    clock = iter(range(100))
    n = run_terminal(items, log, 'a1', input_fn=lambda _: next(answers), output_fn=shown.append,
                     clock=lambda: float(next(clock)), wall=lambda: '2026-10-14T00:00:00Z')
    assert n == 2 and all('ratio' not in s for s in shown)
    events = log.events()
    assert [(e['match_id'], e['A'], e['subtype']) for e in events] == [('m0', 'same', None),
                                                                      ('m1', 'different', 'N4')]
    more = iter(['i', ''])
    assert run_terminal(items, log, 'a1', input_fn=lambda _: next(more), output_fn=lambda _: None) == 1
    assert len(log.events()) == 3


def test_consolidate_agreement_disagreement_adjudication():
    meta = {('p', f'm{i}'): {'older': {'rva': 1, 'size': 1, 'body_sha256': H['w1']},
                             'newer': {'rva': 1, 'size': 1, 'body_sha256': H['w2']},
                             'sampling': {'stratum': 'natural', 'stage': 'S1', 'p_incl': 0.5}} for i in range(3)}
    ev = [{'pair': 'p', 'match_id': 'm0', 'annotator': 'a1', 'phase': 'blind', 'A': 'same'},
          {'pair': 'p', 'match_id': 'm0', 'annotator': 'a2', 'phase': 'blind', 'A': 'same'},
          {'pair': 'p', 'match_id': 'm1', 'annotator': 'a1', 'phase': 'blind', 'A': 'same'},
          {'pair': 'p', 'match_id': 'm1', 'annotator': 'a2', 'phase': 'blind', 'A': 'different'},
          {'pair': 'p', 'match_id': 'm2', 'annotator': 'a1', 'phase': 'blind', 'A': 'same'},
          {'pair': 'p', 'match_id': 'm2', 'annotator': 'a2', 'phase': 'blind', 'A': 'different'},
          {'pair': 'p', 'match_id': 'm2', 'annotator': 'a3', 'phase': 'adjudication', 'A': 'different'},
          {'pair': 'p', 'match_id': 'm0', 'annotator': 'a1', 'phase': 'reveal', 'A': 'different'}]
    records, stats = consolidate(ev, meta)
    assert [(r['match_id'], r['A'], r['adjudicated']) for r in records] == [('m0', 'same', False),
                                                                           ('m2', 'different', True)]
    assert stats == {'pending': [('p', 'm1')], 'reveal_changes': 1}
    load_labels(b'\n'.join(json.dumps(r).encode() for r in records))  # valid calibration-labels/1


def test_kappa_hand_computed_and_ci():
    a = ['same'] * 40 + ['different'] * 10
    b = ['same'] * 38 + ['different'] * 2 + ['different'] * 9 + ['same']
    assert raw_agreement(a, b) == pytest.approx(47 / 50)
    pe = (40 / 50) * (39 / 50) + (10 / 50) * (11 / 50)
    assert cohen_kappa(a, b) == pytest.approx((47 / 50 - pe) / (1 - pe))
    assert cohen_kappa(['same'] * 5, ['same'] * 5) is None
    ci = kappa_ci(a, b, b_count=300)
    assert ci['lo'] <= ci['kappa'] <= ci['hi'] and ci == kappa_ci(a, b, b_count=300)
    rep = agreement_report([(x, y, f'L{i % 7}', 'N1' if i % 5 == 0 else None)
                            for i, (x, y) in enumerate(zip(a, b, strict=True))], b_count=200)
    assert rep['meets_threshold'] is False and 'N1' in rep['subtypes']


# ---- reports and locked test --------------------------------------------------------------------------------

def test_report_is_deterministic_verifiable_and_marks_synthetic():
    per = {'G': {'gates': {g: {'status': 'insufficient-data', 'reasons': ('x',)} for g in ('G0', 'G1', 'G2', 'G3')},
                 'strata': {'N1': {'insufficient': True}}, 'precision': {'point': 0.9, 'lo': 0.8, 'hi': 1.0},
                 'value': 1 / 3}}
    r1 = make_report(prereg_sha=None, corpus_manifest_sha=None, label_set_sha=None, tool_git='t', dataset={'n': 1},
                     per_profile=per, synthetic=True)
    r2 = make_report(prereg_sha=None, corpus_manifest_sha=None, label_set_sha=None, tool_git='t', dataset={'n': 1},
                     per_profile=per, synthetic=True)
    assert canonical_json(r1) == canonical_json(r2) and verify_report(r1)
    assert r1['per_profile']['G']['value'] == 0.333333333333  # 12 significant digits
    assert 'SYNTHETIC' in r1['claim'] and any('N1' in b for b in r1['blind_spots'])
    assert not verify_report(dict(r1, tool_git='u'))
    md = render_markdown(r1)
    assert r1['report_sha256'][:12] in md and 'insufficient-data' in md


def test_locked_test_runs_once_per_preregistration(tmp_path):
    sha = 'a' * 64
    out = run_locked_test(tmp_path, sha, lambda: {'precision': 0.97}, now=lambda: 't0')
    assert out['result'] == {'precision': 0.97}
    with pytest.raises(LockedTestError):
        run_locked_test(tmp_path, sha, lambda: {'precision': 0.99})
    crashed = 'b' * 64
    with pytest.raises(RuntimeError):
        run_locked_test(tmp_path, crashed, lambda: (_ for _ in ()).throw(RuntimeError('boom')))
    with pytest.raises(LockedTestError):  # a crashed run still counts as the one look
        run_locked_test(tmp_path, crashed, lambda: {})
    with pytest.raises(LockedTestError):
        run_locked_test(tmp_path, 'not-a-sha', lambda: {})


def test_schemas_render_and_committed_copies_are_current():
    rendered = render()
    assert set(rendered) == {'CalibrationArtifact.json', 'CorpusManifest.json', 'LabelRecord.json',
                             'CalibrationReport.json'}
    folder = ROOT / 'docs' / 'schemas' / 'calibration'
    for name, text in rendered.items():
        assert (folder / name).read_text(encoding='utf-8') == text


# ---- train/serve identity --------------------------------------------------------------------------------------

def test_train_serve_identity_through_features_artifact_and_runtime_predict():
    """Rows built by the shipped features.py in training give the same probability in the shipped runtime."""
    matches, rz_rows = [], []
    for i in range(120):
        addr = 0x1000 + 0x100 * i
        old = FunctionRecord(artifact_id='o', run_id='r', name=f'f{i}', address=hex(addr), callees=['a'] * (i % 4),
                             metadata={'upstream_similarity': round(det_uniform('g', i), 3), 'length': 50 + i})
        new = FunctionRecord(artifact_id='n', run_id='r', name=f'f{i}', address=hex(addr),
                             metadata={'length': 40 + 2 * i} if i % 7 else {})
        matches.append(FunctionMatch(id=f'm{i:03d}', run_id='r', category='modified', older=[old], newer=[new],
                                     match_types=['SymbolsHash'] if i % 2 else ['StructuralGraphHash']))
        rz_rows.append(SecondaryMatch(engine='rz-diff', engine_version='0.9.1', older_address=addr, newer_address=addr,
                                      older_name=None, newer_name=None,
                                      similarity_milli=int(det_uniform('r', i) * 1000), similarity_text='x',
                                      confidence_milli=None, confidence_text=None, flags=(),
                                      algorithm='levenshtein-bytes'))
    rset = SecondaryMatchSet(contract='secondary/2', engine='rz-diff', engine_version='0.9.1', older_sha256='a' * 64,
                             newer_sha256='b' * 64, file_sha256='c' * 64, matches=tuple(rz_rows),
                             image_base_subtracted='no')
    report = reconcile(matches, rset)
    ctx = ExtractionContext(arch='x64', toolchain='clang')
    feats = [extract(m, (report,), ctx) for m in matches]
    names = list(feature_names('G+R'))
    assert all(f.profile == 'G+R' for f in feats)
    med = medians([f.as_dict() for f in feats], names)
    rows = [Row(f.match_id, f'L{i % 6}', impute(f.as_dict(), names, med),
                int(det_uniform('y', i) < 0.3 + 0.6 * f.as_dict()['G.ratio']), 1.0, 'natural', 'G+R')
            for i, f in enumerate(feats)]
    kinds = [next(s.kind for s in FEATURES if s.name == n) for n in names]
    scale = tuple(k == 'num' for k in kinds)
    mu, sd, beta = fit_base(rows, 1.0, scale)
    scores = {r.id: logit_score(beta, standardise_apply(r.x, mu, sd)) for r in rows}
    model = FittedModel(1.0, tuple(mu), tuple(sd), tuple(beta), fit_calibrator('platt', rows, scores))
    cont = [n for n, k in zip(names, kinds, strict=True) if k == 'num']
    ood = ood_fit([dict(zip(names, r.x, strict=True)) for r in rows], [1.0] * len(rows), cont,
                  [dict(f.categories) for f in feats], ['rz-diff 0.9.1'])
    art_doc = build_artifact(model=model, profile='G+R', names=names, kinds=kinds, med=med, ood=ood, tau=None,
                             tau_low=None, domain={'engines': {'rz-diff': ['0.9.1']}, 'toolchains': ['clang'],
                                                   'arch': ['x64'], 'corpus_id': 'synthetic', 'n_pairs': 1,
                                                   'n_lineages': 6, 'prevalence': 0.5, 'known_blind_spots': []},
                             evidence={'preregistration_sha256': None, 'report_sha256': None,
                                       'corpus_manifest_sha256': None, 'label_set_sha256': None,
                                       'tool_git': 'test', 'gates': {}},
                             model_id='identity', created=dt.date(2026, 10, 14))
    art = parse_artifact(canonical_json(art_doc), today=dt.date(2026, 10, 14))
    for f, r in zip(feats, rows, strict=True):
        served = predict(f, art)
        assert served.p == pytest.approx(model.predict(r.x), abs=2e-6)  # 12-digit artifact rounding only
        assert not [x for x in served.flags if x.startswith('hard:unseen')]
