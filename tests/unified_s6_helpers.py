"""Shared builders for the SPEC-31 S6a tests: label documents built through the SPEC-32 contract (nothing is compiled, no image
exists) and bench rows with the shape `tools/unified/bench.py` produces."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT, ROOT / 'src'):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.unified import bench  # noqa: E402
from tools.unified.mutations import classes  # noqa: E402

SOURCE = {'aa': 'same-source', 'noise': 'same-source', 'release': 'source-diff', 'cve': 'fix-diff',
          'control': 'source-diff', 'mutation': 'planted-mutation', 'authored': 'authored-truth'}
METHOD = {'aa': 'aa-rebuild', 'noise': 'toolchain-noise', 'release': 'release-pair', 'cve': 'cve-pair',
          'control': 'case-card', 'mutation': 'mutation', 'authored': 'suite'}


def side(sha, name='x.dll'):
    return {'sha256': sha, 'debug_sha256': sha[::-1], 'pdb_sha256': None, 'size': 4096, 'file_name': name,
            'image_base': 0x180000000, 'source': {'suite': 'tests/x', 'version': 'v1', 'license_spdx': 'MIT'},
            'build': {'profile': 'msvc-free', 'compiler': 'clang', 'compiler_version': 'clang 18', 'opt': 'O2',
                      'recipe_digest': 'c' * 64, 'link_order': 'sorted', 'variant': ''}}


def function(name, rva, source, label='unchanged'):
    kind = 'const-change' if label == 'changed' else None
    return {'name': name, 'file': 'x.c', 'variant': None, 'old_rva': rva, 'new_rva': rva, 'old_size': 16,
            'new_size': 16, 'identity': 'same', 'label': label, 'change_kind': kind, 'body': 'identical',
            'label_source': source, 'check': 'ok', 'taxonomy': [], 'notes': ''}


def label_doc(pair_id, stratum, *, method=None, older='a' * 64, newer='b' * 64, case=None, target=None, project='p'):
    source = SOURCE[stratum]
    functions = [function('f0', 0x1000, source), function('f1', 0x1100, source)]
    if target:
        functions.append(function(target, 0x1200, source, 'changed'))
    doc = {'contract': 'known-answer-labels/1', 'pair_id': pair_id, 'stratum': stratum,
           'method': method or METHOD[stratum], 'project': project, 'lineage': f'L-{project}', 'family': 'synthetic',
           'older': side(older), 'newer': side(newer), 'label_source': source, 'functions': functions,
           'summary': {}, 'case': case or {}, 'notes': []}
    return C.load_labels(C.dump_json(C.finalize_labels(doc)))


def mutation_doc(pair_id, cid='constant', target='ka_constant_00'):
    return label_doc(pair_id, 'mutation', target=target,
                     case={'unified_class': cid, 'target': target, 'verdicts': list(classes.BY_ID[cid].verdicts)})


def row(stage='ladder', n=10_000, *, ladder=1.0, sides=0.5, ingest=1.0, rss=100 * 2**20, ticks=None, **counts):
    seconds = {'sides': sides, 'ladder': ladder, 'total': sides + ladder} if stage == 'ladder' else {'ingest': ingest}
    base = {'ticks': 6 * n if ticks is None else ticks, 'pairs': n, 'truth': n, 'right': n, 'wrong': 0, 'spurious': 0,
            'waves': 10, 'status': 'complete', 'limits_hit': ''} if stage == 'ladder' else {
        'functions': n, 'instructions': n * 10, 'generated_functions': n, 'generated_instructions': n * 10,
        'content_digest': 'd' * 64}
    return {'stage': stage, 'n': n, 'status': 'measured', 'seconds': seconds, 'peak_rss_bytes': rss,
            'counts': {**base, **counts}, 'derived': {}, 'error': None}


def evaluated(*rows):
    return bench.evaluate([copy.deepcopy(r) for r in rows])
