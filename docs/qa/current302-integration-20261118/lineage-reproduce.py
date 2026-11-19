"""Independent authored lineage controls. No I/O except this result; no target bytes."""
from pathlib import Path
import json
import sys
import time

from patchtrace.kbcorrelation import lineage, resolver
from patchtrace.kbcorrelation.products import scope_for
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.store import KbcStoreError

SCOPE = scope_for('1' * 64, 'client', 'Windows 11 Version 24H2 for x64-based Systems')


def mapping(sha, kb, build, day='2099-02-01', **extra):
    return {'sha256': sha * 64, 'kb': kb, 'version_key': '11-24H2', 'release_date': day,
            'release_version': build, 'size': 8192, 'machine_type': 0x8664,
            'variant': 'full', 'heading_class': 'standard', 'download': 'direct',
            'record_sha256': 'd' * 64} | extra


def observe(items, *, limit=1000):
    rows, rejected = lineage.index_rows(items, file_name='example.sys')
    assert rejected == 0
    result = resolver.resolve(rows, kb='KB5000003', scope=SCOPE, file_name='example.sys',
                              fixed_build='26100.200', limit=limit)
    choice = None
    try:
        picked = KbService._pick_pair([result], None)
        if picked:
            choice = {'older': picked.older.sha256[0], 'newer': picked.newer.sha256[0], 'grade': picked.grade}
    except KbcStoreError as error:
        choice = {'error_code': error.code, 'message': str(error)}
    return {'changed_in_kb': result.changed_in_kb, 'last_changed_in': result.last_changed_in,
            'ambiguous': getattr(result, 'ambiguous', 'FIELD_ABSENT'), 'truncated': result.truncated,
            'blockers': result.blockers, 'note': result.note, 'default_choice': choice,
            'pairs': [{'id': pair.pair_id, 'older': pair.older.sha256[0], 'newer': pair.newer.sha256[0],
                       'grade': pair.grade, 'fix_boundary': pair.fix_boundary,
                       'reason_codes': pair.reason_codes} for pair in result.pairs]}


old = mapping('a', 'KB5000001', '26100.100', '2099-01-01')
target = mapping('b', 'KB5000003', '26100.200')
cases = {
    'different_build_families_equal_time': [mapping('a', 'KB5000001', '26000.100'), target],
    'hidden_missing_build_same_time': [mapping('c', 'KB5000000', None), mapping('a', 'KB5000001', '26100.100'), target],
    'prior_variant_sorts_before': [mapping('a', 'KB5000001', '26100.100', '2099-01-01'), mapping('b', 'KB5000001', '26100.100', '2099-01-01'), target],
    'prior_variant_sorts_after': [mapping('b', 'KB5000001', '26100.100', '2099-01-01'), mapping('c', 'KB5000001', '26100.100', '2099-01-01'), target],
    'one_target_variant_unavailable': [old, target, mapping('c', 'KB5000003', '26100.200', download=None, variant='delta')],
    'unambiguous_control': [old, target],
}
results = {name: observe(items) for name, items in cases.items()}
results['truncated_choices'] = observe([old, target, mapping('c', 'KB5000003', '26100.200')], limit=1)

many = [old] + [mapping('b', 'KB5000003', '26100.200') | {'sha256': f'{i+1:064x}'} for i in range(100)]
original, calls = resolver.propose_index_pair, []


def counted(*args, **kwargs):
    calls.append(1)
    return original(*args, **kwargs)


resolver.propose_index_pair = counted
started = time.monotonic()
results['bounded_enumeration'] = observe(many, limit=7)
results['bounded_enumeration'].update(proposals_evaluated=len(calls), elapsed_seconds=time.monotonic()-started)
resolver.propose_index_pair = original
document = {'source_module': lineage.__file__, 'resolver_module': resolver.__file__, 'target_bytes': False,
            'cases': results}
with Path(sys.argv[1]).open('x') as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write('\n')
for name, result in results.items():
    print(json.dumps({'case': name, **{k: result[k] for k in ('changed_in_kb', 'last_changed_in', 'ambiguous', 'truncated', 'default_choice')},
                      'pairs': [{k: pair[k] for k in ('older', 'newer', 'grade', 'fix_boundary')} for pair in result['pairs']],
                      'proposals_evaluated': result.get('proposals_evaluated')}))
