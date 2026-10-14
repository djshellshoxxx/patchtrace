"""Generate JSON schemas and valid/invalid examples for the SPEC-32 contracts into docs/schemas/corpus/.

Run from the repository root: `PYTHONPATH=src python -m tools.calibration.tier_r.schemas` (or the `schemas` CLI verb).
Kept separate so the shared tools/generate_schemas.py is untouched. Example names encode the contract:
`{valid|invalid}-{labels|recipes|mutation|report}-<what>.json`; `check_example` loads one with the strict loader.
"""
from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path

from ..common import digest
from . import contracts as C

SCHEMAS = ((C.KnownAnswerLabels, 'known-answer-labels/1'), (C.RecipeBook, 'tier-r-recipes/1'),
           (C.Recipe, 'tier-r-recipe/1'), (C.MutationCase, 'mutation-case/1'), (C.TierRReport, 'tier-r-report/1'))
OUT = Path('docs/schemas/corpus')
_H = {k: hashlib.sha256(f'example-{k}'.encode()).hexdigest() for k in 'abcdefr'}


def render() -> dict[str, str]:
    out = {}
    for model, ident in SCHEMAS:
        schema = model.model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/{ident}/{model.__name__}.json'
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        out[f'{model.__name__}.json'] = json.dumps(schema, indent=2, sort_keys=True) + '\n'
    return out


def _side(sha: str, debug: str, version: str) -> dict:
    return {'sha256': sha, 'debug_sha256': debug, 'pdb_sha256': None, 'size': 4096, 'file_name': 'tiny.dll',
            'image_base': 0x180000000, 'source': {'suite': '_template/tiny', 'version': version, 'license_spdx': 'MIT'},
            'build': {'profile': 'msvc-free', 'compiler': 'clang', 'compiler_version': '18.1.3', 'opt': 'O2',
                      'recipe_digest': _H['r']}}


def _record(name: str, old, new, label: str, identity: str = 'same', kind=None, body=None) -> dict:
    return {'name': name, 'file': 'tiny.c', 'variant': None, 'old_rva': old, 'new_rva': new,
            'old_size': None if old is None else 16, 'new_size': None if new is None else 16, 'identity': identity,
            'label': label, 'change_kind': kind,
            'body': body or ('identical' if old is not None and new is not None else 'n/a'),
            'label_source': 'authored-truth', 'check': 'ok', 'taxonomy': [], 'notes': ''}


def example_labels() -> dict:
    return C.finalize_labels({
        'contract': 'known-answer-labels/1', 'pair_id': 'ours-template-tiny-v1-v2', 'stratum': 'authored',
        'method': 'suite', 'project': 'tiny', 'lineage': 'L-ours-_template-tiny', 'family': 'synthetic',
        'older': _side(_H['a'], _H['b'], 'v1'), 'newer': _side(_H['c'], _H['d'], 'v2'),
        'label_source': 'authored-truth',
        'functions': [_record('tiny_add', 0x1000, 0x1000, 'unchanged'),
                      _record('tiny_clamp', 0x1010, 0x1010, 'changed', kind='bounds-check-added', body='different'),
                      _record('tiny_sum_to', 0x1020, 0x1030, 'cosmetic', kind='cosmetic', body='address-only'),
                      _record('tiny_old_only', 0x1040, None, 'no-counterpart', 'no-counterpart'),
                      _record('tiny_new_only', None, 0x1050, 'no-counterpart', 'no-counterpart')],
        'summary': {}, 'case': {'intent': 'example only: not produced by a build'}, 'notes': []})


def example_recipes() -> dict:
    return {'contract': 'tier-r-recipes/1', 'excluded': [{'project': 'example', 'reason': 'illustration'}],
            'recipes': [{'contract': 'tier-r-recipe/1', 'project': 'zlib', 'family': 'compression',
                         'upstream_git': 'https://github.com/madler/zlib.git', 'license_spdx': 'Zlib',
                         'license_file': 'LICENSE', 'license_evidence': 'example', 'libc': 'mingw',
                         'output': 'zlib1.dll', 'sources': ['*.c'], 'exclude': ['gz*.c'], 'include_dirs': ['.'],
                         'defines': ['ZLIB_DLL'], 'pins': [{'ref': 'v1.3', 'commit': 'a' * 40,
                                                            'license_sha256': _H['a']}]}]}


def example_mutation() -> dict:
    return {'contract': 'mutation-case/1', 'case_id': 'tiny-cmp-flip-7', 'operator': 'cmp-flip', 'kind': 'semantic',
            'seed': 7, 'base': {'suite': '_template/tiny', 'version': 'v1', 'license_spdx': 'MIT'},
            'target_file': 'tiny.c', 'target_function': 'tiny_clamp',
            'site': {'file': 'tiny.c', 'line': 6, 'column': 11, 'before': '>', 'after': '>='},
            'attempts': 1, 'rejected': [], 'helper': None, 'moved_function': None, 'patch_sha256': _H['e']}


def example_report() -> dict:
    metrics = {'pairs': 1, 'truth_same': 3, 'identity_tp': 3, 'identity_fp': 0, 'identity_fn': 0,
               'identity_precision': 1.0, 'identity_recall': 1.0, 'changed_truth': 1, 'changed_tp': 1,
               'changed_fp': 1, 'changed_fn': 0, 'changed_precision': 0.5, 'changed_recall': 1.0,
               'matched_negatives': 2, 'fp_rate': 0.5, 'cosmetic_matched': 1, 'cosmetic_flagged': 1,
               'ignored_predictions': 0, 'ambiguous_records': 0}
    report = {'contract': 'tier-r-report/1', 'symbols': 'hidden',
              'inputs': [{'pair_id': 'ours-template-tiny-v1-v2', 'stratum': 'authored', 'labels_digest': _H['f']}],
              'engines': [{'engine': 'rz-diff', 'status': 'ok', 'version': '0.9.1', 'reason': None, 'runs': 1,
                           'failures': 0},
                          {'engine': 'bindiff', 'status': 'blocked', 'version': None,
                           'reason': 'example: no BinDiff installation and no imported .BinDiff files', 'runs': 0,
                           'failures': 0}],
              'strata': {'authored': {'rz-diff': metrics}},
              'pairs': [{'pair_id': 'ours-template-tiny-v1-v2', 'stratum': 'authored', 'engine': 'rz-diff',
                         'status': 'ok', 'reason': None, 'metrics': metrics, 'output_sha256': _H['a']}],
              'wrong_matches': [], 'wrong_matches_truncated': 0, 'notes': ['example only']}
    report['report_sha256'] = digest(report, 'report_sha256')
    return report


def _invalid(base: dict, mutate: Callable[[dict], None], *, redigest: str | None = 'digest_sha256') -> dict:
    doc = copy.deepcopy(base)
    mutate(doc)
    if redigest:
        doc[redigest] = digest(doc, redigest)
    return doc


def examples() -> dict[str, dict | list]:
    labels, report = example_labels(), example_report()
    return {
        'valid-labels-template.json': labels,
        'valid-recipes-zlib.json': example_recipes(),
        'valid-mutation-cmp-flip.json': example_mutation(),
        'valid-report-template.json': report,
        'invalid-labels-tampered.json': _invalid(labels, lambda d: d['functions'][0].update(notes='edited'),
                                                 redigest=None),
        'invalid-labels-nocounterpart-two-sides.json': _invalid(
            labels, lambda d: [f.update(new_rva=0x2000, new_size=16) for f in d['functions']
                               if f['label'] == 'no-counterpart' and f['new_rva'] is None]),
        'invalid-labels-changed-without-kind.json': _invalid(
            labels, lambda d: [f.update(change_kind=None) for f in d['functions'] if f['label'] == 'changed']),
        'invalid-labels-unknown-field.json': _invalid(labels, lambda d: d.update(binary_bytes='TVqQ')),
        'invalid-recipes-gpl.json': _invalid(example_recipes(), lambda d: d['recipes'][0].update(
            license_spdx='GPL-3.0-only'), redigest=None),
        'invalid-recipes-shell-define.json': _invalid(example_recipes(), lambda d: d['recipes'][0].update(
            defines=['X=`id`']), redigest=None),
        'invalid-mutation-kind.json': _invalid(example_mutation(), lambda d: d.update(kind='cosmetic'), redigest=None),
        'invalid-report-digest.json': _invalid(report, lambda d: d.update(symbols='visible'), redigest=None),
    }


LOADERS = {'labels': C.load_labels, 'recipes': C.load_recipes, 'mutation': C.load_mutation_case,
           'report': C.load_report}


def check_example(path: Path) -> tuple[bool, str]:
    kind = path.name.split('-')[1]
    try:
        LOADERS[kind](path.read_bytes())
    except C.ContractError as exc:
        return False, str(exc)[:300]
    return True, 'ok'


def write_all(root: Path = OUT) -> list[Path]:
    root.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in render().items():
        (root / name).write_text(text, encoding='utf-8', newline='\n')
        written.append(root / name)
    folder = root / 'examples'
    folder.mkdir(exist_ok=True)
    for name, doc in examples().items():
        (folder / name).write_bytes(C.dump_json(doc))
        written.append(folder / name)
    return written


def main() -> int:
    for path in write_all():
        print(path.as_posix())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
