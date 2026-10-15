"""Builders shared by the test_train_* modules: a SYNTHETIC Tier R world (hand-made label documents and engine outputs
whose similarity is correlated with the truth by a deterministic generator). It exercises the training pipeline and
never says anything about a real engine or real binaries."""
from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.common import canonical_json, det_uniform  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import schemas as S  # noqa: E402

PROFILES = ('mingw-gcc', 'mingw-clang', 'msvc-free')
METHOD = {'authored': ('suite', 'authored-truth'), 'aa': ('aa-rebuild', 'same-source'),
          'noise': ('toolchain-noise', 'same-source'), 'mutation': ('mutation', 'planted-mutation')}


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def make_pair_labels(lineage: str, *, stratum: str = 'authored', n_funcs: int = 24, toolchain: str = 'mingw-gcc',
                     family: str = 'fam0', tag: str | None = None) -> C.KnownAnswerLabels:
    method, source = METHOD[stratum]
    tag = tag or f'{lineage}-{stratum}'
    doc = copy.deepcopy(S.example_labels())
    for side, key in (('older', 'o'), ('newer', 'n')):
        d = doc[side]
        d['sha256'], d['debug_sha256'] = sha(f'{tag}-{key}'), sha(f'{tag}-{key}-dbg')
        d['source'] = {'suite': f'ours/{lineage}', 'version': 'v1' if key == 'o' else 'v2', 'license_spdx': 'MIT'}
        d['build'] = dict(d['build'], profile=toolchain, compiler='clang' if 'clang' in toolchain or 'msvc' in toolchain
                          else 'gcc')
    if stratum == 'aa':
        doc['newer'] = copy.deepcopy(doc['older'])
    funcs = []
    for i in range(n_funcs):
        label = ('unchanged', 'changed', 'cosmetic', 'unchanged')[i % 4]
        rva = 0x1000 + 0x20 * i
        kind = {'changed': 'bounds-check-added', 'cosmetic': 'cosmetic'}.get(label)
        body = {'unchanged': 'identical', 'changed': 'different', 'cosmetic': 'address-only'}[label]
        rec = S._record(f'{lineage}_f{i}', rva, rva, label, kind=kind, body=body)
        rec['label_source'] = source
        funcs.append(rec)
    for i in range(3):                         # functions with no counterpart on either side
        old = S._record(f'{lineage}_gone{i}', 0x8000 + 0x20 * i, None, 'no-counterpart', 'no-counterpart')
        new = S._record(f'{lineage}_new{i}', None, 0x9000 + 0x20 * i, 'no-counterpart', 'no-counterpart')
        old['label_source'] = new['label_source'] = source
        funcs += [old, new]
    doc.update(pair_id=f'{lineage}-{stratum}', stratum=stratum, method=method, label_source=source, functions=funcs,
               project=lineage, lineage=lineage, family=family, case={'intent': 'synthetic training fixture'})
    return C.load_labels(C.dump_json(C.finalize_labels(doc)))


def engine_output(labels: C.KnownAnswerLabels, engine: str, seed='w', noise: float = 0.30) -> dict:
    """`tier-r-engine-output/1` document: truth pairs with a similarity that drops with the change, plus wrong proposals
    (neighbouring functions, and old-only functions matched to new-only ones) with low similarity."""
    preds = []
    funcs = [f for f in labels.functions if f.identity == 'same']
    for i, f in enumerate(funcs):
        base = {'unchanged': 0.995, 'cosmetic': 0.96, 'changed': 0.80}[f.label]
        sim = base + noise * (det_uniform(seed, engine, labels.pair_id, 's', i) - 0.5)
        sim = min(1.0, max(0.0, sim))
        if det_uniform(seed, engine, labels.pair_id, 'miss', i) < 0.04:
            continue                                       # the engine misses a few pairs
        preds.append({'old_rva': f.old_rva, 'new_rva': f.new_rva, 'changed': sim < 0.97,
                      'similarity_milli': round(sim * 1000), 'old_name': f.name, 'new_name': f.name})
    for i, (a, b) in enumerate(zip(funcs[::3], funcs[1::3], strict=False)):
        if det_uniform(seed, engine, labels.pair_id, 'wrong', i) < 0.7:
            sim = 0.45 + 0.40 * det_uniform(seed, engine, labels.pair_id, 'ws', i)
            preds.append({'old_rva': a.old_rva, 'new_rva': b.new_rva, 'changed': True,
                          'similarity_milli': round(sim * 1000), 'old_name': a.name, 'new_name': b.name})
    olds = sorted(f.old_rva for f in labels.functions if f.identity == 'no-counterpart' and f.old_rva is not None)
    news = sorted(f.new_rva for f in labels.functions if f.identity == 'no-counterpart' and f.new_rva is not None)
    for i, (o, n) in enumerate(zip(olds, news, strict=False)):
        if det_uniform(seed, engine, labels.pair_id, 'nc', i) < 0.8:
            sim = 0.2 + 0.4 * det_uniform(seed, engine, labels.pair_id, 'ncs', i)
            preds.append({'old_rva': o, 'new_rva': n, 'changed': True, 'similarity_milli': round(sim * 1000),
                          'old_name': None, 'new_name': None})
    preds.sort(key=lambda p: (p['old_rva'], p['new_rva']))
    return {'contract': 'tier-r-engine-output/1', 'engine': engine, 'version': '0.9.1', 'symbols': 'hidden',
            'older_sha256': labels.older.sha256, 'newer_sha256': labels.newer.sha256, 'implicit_unchanged': False,
            'predictions': preds, 'old_only_rvas': [], 'new_only_rvas': [], 'ignored_unaddressed': 0}


def write_world(folder: Path, *, n_lineages: int = 14, n_funcs: int = 24, engines=('ghidriff', 'rz-diff'),
                controls: bool = False, seed='w') -> tuple[Path, Path]:
    """Writes labels/ and outputs/ under `folder`; lineages cycle through three toolchains and four families."""
    labels_dir, out_dir = folder / 'labels', folder / 'outputs'
    labels_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    for i in range(n_lineages):
        lineage = f'proj{i:02d}'
        strata = ['authored'] + (['aa', 'mutation'] if controls and i < 3 else [])
        for stratum in strata:
            labels = make_pair_labels(lineage, stratum=stratum, n_funcs=n_funcs, toolchain=PROFILES[i % 3],
                                      family=f'fam{i % 4}',
                                      tag=f'{lineage}-{stratum}' + ('-m' if stratum == 'mutation' else ''))
            (labels_dir / f'{labels.pair_id}.json').write_bytes(C.dump_json(labels.model_dump(mode='json')))
            for engine in engines:
                doc = engine_output(labels, engine, seed)
                (out_dir / f'{labels.pair_id}.{engine}.json').write_bytes(canonical_json(doc))
    return labels_dir, out_dir


def test_world_is_deterministic(tmp_path):
    a = write_world(tmp_path / 'a', n_lineages=2)
    b = write_world(tmp_path / 'b', n_lineages=2)
    names = sorted(p.name for p in a[0].iterdir())
    assert names and names == sorted(p.name for p in b[0].iterdir())
    for name in names:
        assert (a[0] / name).read_bytes() == (b[0] / name).read_bytes()
