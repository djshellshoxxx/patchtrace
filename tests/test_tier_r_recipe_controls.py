"""LBL-32 recipe-control planning and dispatch; no fetches, compilers or analysis engines run here."""
from __future__ import annotations

import copy
import json
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import shard as S  # noqa: E402
from tools.calibration.tier_r.schemas import example_recipes  # noqa: E402

CATALOGUE = Path('tools/calibration/tier_r/catalogue')


def card(ident='zlib-v1-v2', *, project='zlib', old=('v1', 'a'), new=('v2', 'b'), license_spdx='Zlib'):
    return {'contract': 'case-card/1', 'id': ident, 'project': project,
            'upstream_git': 'https://github.com/madler/zlib.git', 'license_spdx': license_spdx,
            'license_evidence': 'synthetic fixture', 'old': {'ref': old[0], 'commit': old[1] * 40},
            'new': {'ref': new[0], 'commit': new[1] * 40}, 'kind': 'release', 'semantic_change': True}


def write_cards(root, relative, cards):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cards), encoding='utf-8')
    return path


@pytest.fixture
def catalogue(tmp_path):
    root = tmp_path / 'repo'
    book = example_recipes()
    book['recipes'][0]['pins'] = [{'ref': f'v{i}', 'commit': char * 40, 'license_sha256': char * 64}
                                 for i, char in enumerate('abc', 1)]
    write_cards(root, CATALOGUE / 'recipes.json', book)
    write_cards(root, CATALOGUE / 'releases.json', [card()])
    write_cards(root, CATALOGUE / 'cves.json', [])
    suite = root / 'corpus/ours/_template/tiny/suite.json'
    suite.parent.mkdir(parents=True)
    suite.write_text('{}', encoding='utf-8')
    return root


def plan_cases(root, subset='full', seed=7):
    plan = S.make_plan(root, subset=subset, seed=seed, shards=3)
    return sorted(case for shard in plan['shards'] for case in shard['cases'])


@pytest.mark.parametrize(('relative', 'text'), [
    (CATALOGUE / 'recipes.json', '{"contract":"tier-r-recipes/1","recipes":[],"recipes":[]}'),
    (CATALOGUE / 'releases.json', '[{"id": "unfinished"}'),
    (CATALOGUE / 'cves.json', json.dumps([card()])[:-1] + ', NaN]'),
    (Path('corpus/catalog/found.json'), '{"not": "a card array"}'),
], ids=['duplicate-recipe-key', 'malformed-card-json', 'non-finite-card-json', 'found-card-shape'])
def test_plan_rejects_invalid_catalogue_json(catalogue, relative, text):
    path = catalogue / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    with pytest.raises(C.ContractError):
        plan_cases(catalogue)


@pytest.mark.parametrize('commit', ['', 'short', 'a' * 39, 'G' * 40, None])
def test_plan_rejects_invalid_card_pin(catalogue, commit):
    bad = card()
    bad['old']['commit'] = commit
    write_cards(catalogue, CATALOGUE / 'releases.json', [bad])
    with pytest.raises(C.ContractError):
        plan_cases(catalogue)


def test_plan_requires_valid_recipe_book(catalogue):
    book = example_recipes()
    book['recipes'].append(copy.deepcopy(book['recipes'][0]))
    write_cards(catalogue, CATALOGUE / 'recipes.json', book)
    with pytest.raises(C.ContractError, match='duplicate recipe project'):
        plan_cases(catalogue)


def test_plan_does_not_hide_unreadable_recipe_book(catalogue):
    (catalogue / CATALOGUE / 'recipes.json').unlink()
    with pytest.raises(OSError):
        plan_cases(catalogue)


@pytest.mark.parametrize('relative', [CATALOGUE / 'releases.json', CATALOGUE / 'cves.json',
                                      Path('corpus/catalog/found.json')],
                         ids=['same-file', 'curated-files', 'found-file'])
def test_duplicate_card_ids_fail_before_eligibility_filter(catalogue, relative):
    duplicate = card(project='no-recipe', license_spdx='GPL-2.0-only')
    same_file = relative.name == 'releases.json'
    write_cards(catalogue, relative, [card(), duplicate] if same_file else [duplicate])
    with pytest.raises(C.ContractError, match='duplicate id') as caught:
        plan_cases(catalogue)
    message = str(caught.value)
    assert 'tools/calibration/tier_r/catalogue/releases.json[0]' in message
    assert f'{relative.as_posix()}[{int(same_file)}]' in message


def test_plan_uses_shared_catalogue_scope_and_one_read_per_file(catalogue, monkeypatch):
    found = write_cards(catalogue, Path('corpus/catalog/found.json'), [card('zlib-v2-v3', old=('v2', 'b'),
                                                                        new=('v3', 'c'))])
    ignored = write_cards(catalogue, CATALOGUE / 'not-a-catalogue.json', [card('not-a-planned-card')])
    watched = {catalogue / CATALOGUE / name for name in ('recipes.json', 'releases.json', 'cves.json')}
    watched |= {found, ignored}
    reads = Counter()
    original_open = Path.open

    def tracked_open(path, *args, **kwargs):
        if path in watched:
            reads[path] += 1
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', tracked_open)
    cases = plan_cases(catalogue)
    assert [case for case in cases if case.startswith('card:')] == ['card:zlib-v1-v2', 'card:zlib-v2-v3']
    assert reads == Counter({path: 1 for path in watched - {ignored}})


def test_invalid_catalogue_does_not_publish_plan(catalogue, tmp_path, capsys):
    write_cards(catalogue, CATALOGUE / 'cves.json', [card()])
    out = tmp_path / 'plan.json'
    result = S.main(['plan', '--root', str(catalogue), '--seed', '7', '--shards', '3', '--subset', 'cards',
                     '--plan-out', str(out)])
    captured = capsys.readouterr()
    assert result == S.USAGE
    assert not out.exists() and not captured.out
    assert 'duplicate id' in captured.err


@pytest.mark.parametrize(('subset', 'kinds'), [('cards', ('aa',)), ('noise', ('noise',)),
                                             ('full', ('aa', 'noise')), ('smoke', ()), ('suites', ()),
                                             ('mutations', ())])
def test_recipe_controls_cover_both_sides_in_their_subsets(catalogue, subset, kinds):
    cases = plan_cases(catalogue, subset)
    assert {case for case in cases if case.startswith(('aa-card:', 'noise-card:'))} == {
        f'{kind}-card:zlib-v1-v2:{side}' for kind in kinds for side in ('old', 'new')}
    if subset in ('noise', 'full', 'smoke'):
        assert 'noise:_template/tiny' in cases
    if subset in ('suites', 'full', 'smoke'):
        assert 'aa:_template/tiny' in cases


def test_unlicensed_and_unbuildable_cards_get_no_controls(catalogue):
    write_cards(catalogue, CATALOGUE / 'releases.json', [card(), card('unlicensed-card', license_spdx='GPL-2.0-only'),
                                                       card('no-recipe-card', project='no-recipe')])
    assert plan_cases(catalogue, 'cards') == ['aa-card:zlib-v1-v2:new', 'aa-card:zlib-v1-v2:old', 'card:zlib-v1-v2']


def test_shared_pins_have_stable_representatives_across_file_and_record_order(catalogue):
    rows = [card(), card('zlib-v2-v3', old=('v2', 'b'), new=('v3', 'c')), card('zlib-cve-fix')]
    write_cards(catalogue, CATALOGUE / 'releases.json', rows)
    first = S.make_plan(catalogue, subset='full', seed=11, shards=4)
    cases = {case for shard in first['shards'] for case in shard['cases']}
    for kind in ('aa', 'noise'):
        assert {case for case in cases if case.startswith(f'{kind}-card:')} == {
            f'{kind}-card:zlib-cve-fix:old', f'{kind}-card:zlib-cve-fix:new', f'{kind}-card:zlib-v2-v3:new'}
    write_cards(catalogue, CATALOGUE / 'releases.json', [rows[2]])
    write_cards(catalogue, CATALOGUE / 'cves.json', list(reversed(rows[:2])))
    assert S.make_plan(catalogue, subset='full', seed=11, shards=4) == first
    assert {case for case in plan_cases(catalogue, seed=999) if case.startswith(('aa-card:', 'noise-card:'))} == {
        case for case in cases if case.startswith(('aa-card:', 'noise-card:'))}


def test_distinct_refs_of_one_commit_remain_distinct_probes(catalogue):
    write_cards(catalogue, CATALOGUE / 'releases.json', [card(), card('zlib-alias', old=('v1-alias', 'a'))])
    cases = plan_cases(catalogue, 'cards')
    assert {case for case in cases if case.startswith('aa-card:')} == {
        'aa-card:zlib-v1-v2:old', 'aa-card:zlib-alias:old', 'aa-card:zlib-alias:new'}


def test_same_ref_in_different_projects_is_not_deduplicated(catalogue):
    book = example_recipes()
    book['recipes'].append({**copy.deepcopy(book['recipes'][0]), 'project': 'another-project'})
    write_cards(catalogue, CATALOGUE / 'recipes.json', book)
    write_cards(catalogue, CATALOGUE / 'releases.json', [card(), card('another-v1-v2', project='another-project',
                                                                 old=('v1', 'd'), new=('v2', 'e'))])
    assert {case for case in plan_cases(catalogue, 'cards') if case.startswith('aa-card:')} == {
        f'aa-card:{ident}:{side}' for ident in ('zlib-v1-v2', 'another-v1-v2') for side in ('old', 'new')}


@pytest.mark.parametrize('subset', ['cards', 'noise', 'full'])
def test_conflicting_sha_for_same_project_ref_is_refused(catalogue, subset):
    write_cards(catalogue, CATALOGUE / 'releases.json', [card(), card('zlib-v2-v3', old=('v2', 'c'), new=('v3', 'd'))])
    with pytest.raises(S.ShardError, match='conflicting.*zlib.*v2'):
        plan_cases(catalogue, subset)


@pytest.mark.parametrize('side', ['old', 'new'])
def test_missing_side_ref_is_refused(catalogue, side):
    row = card()
    del row[side]['ref']
    write_cards(catalogue, CATALOGUE / 'releases.json', [row])
    with pytest.raises(C.ContractError):
        plan_cases(catalogue)


@pytest.mark.parametrize('field', ['old', 'new', 'project', 'card-url', 'recipe-url'])
def test_innocent_card_id_cannot_hide_microsoft_source(catalogue, field):
    row = card()
    book = example_recipes()
    if field in ('old', 'new'):
        row[field]['ref'] = 'refs/tags/tier-w-source'
    elif field == 'project':
        row['project'] = book['recipes'][0]['project'] = 'microsoft-project'
    elif field == 'card-url':
        row['upstream_git'] = 'https://github.com/microsoft/project.git'
    else:
        book['recipes'][0]['upstream_git'] = 'https://github.com/microsoft/project.git'
    write_cards(catalogue, CATALOGUE / 'releases.json', [row])
    write_cards(catalogue, CATALOGUE / 'recipes.json', book)
    with pytest.raises(S.ShardError, match='refused'):
        plan_cases(catalogue)


def test_smoke_membership_is_unchanged(catalogue):
    assert plan_cases(catalogue, 'smoke') == ['aa:_template/tiny', 'card:zlib-v1-v2',
                                           'mutate:_template/tiny:cmp-flip:7000', 'noise:_template/tiny',
                                           'suite:_template/tiny']


@pytest.mark.parametrize('kind', ['aa', 'noise'])
@pytest.mark.parametrize('side', ['old', 'new'])
def test_recipe_control_fetches_before_dispatching_selected_side(kind, side):
    assert S.case_steps(f'{kind}-card:zlib-v1-v2:{side}') == [
        ['fetch', 'zlib-v1-v2'], [kind, '--card', 'zlib-v1-v2', '--side', side]]


@pytest.mark.parametrize('case', ['aa-card:zlib-v1-v2', 'aa-card:zlib-v1-v2:middle', 'noise-card:zlib-v1-v2:OLD',
                                  'aa-card::old', 'aa-card:../zlib-v1-v2:new', 'noise-card:zlib/../v2:old',
                                  'aa-card:zlib-v1-v2:old:extra', 'noise-card:zlib v1:old',
                                  'aa-card:zlib-v1-v2:old\n', 'noise-card:zlib-v1-v2:new\r\n',
                                  'aa-card:zlib-v1-v2:old ', 'card:zlib-v1-v2\n',
                                  'aa-card:' + 'a' * 129 + ':old'])
def test_recipe_control_ids_require_an_exact_safe_parse(case):
    with pytest.raises(S.ShardError, match='malformed'):
        S.case_steps(case)


@pytest.mark.parametrize('case', ['aa-card:ntoskrnl.exe:old', 'noise-card:tw.pair:new',
                                  'aa-card:Microsoft-project:new', 'noise-card:tier-w/afd.sys:old'])
def test_recipe_control_ids_preserve_microsoft_refusal(case):
    with pytest.raises(S.ShardError, match='refused'):
        S.case_steps(case)


def single_shard(cases):
    plan = {'contract': S.PLAN_CONTRACT, 'seed': 7, 'subset': 'full', 'engines': ['rz-diff'], 'of': 1,
            'cases_total': len(cases), 'shards': [{'shard': 0, 'cases': cases}]}
    plan['plan_sha256'] = S.digest(plan, 'plan_sha256')
    return plan


def test_runner_dispatches_all_recipe_control_sides(monkeypatch):
    monkeypatch.setenv('PATCHTRACE_TIER_R_NO_EVAL', '1')
    cases = [f'{kind}-card:zlib-v1-v2:{side}' for kind in ('aa', 'noise') for side in ('old', 'new')]
    commands = []

    def runner(argv, timeout, env):
        commands.append(argv[3:])
        return 0, json.dumps({'command': argv[3], 'status': 'ok'}), None

    result = S.run_shard(single_shard(cases), 0, runner=runner)
    assert commands == [step for kind in ('aa', 'noise') for side in ('old', 'new') for step in
                        (['fetch', 'zlib-v1-v2'], [kind, '--card', 'zlib-v1-v2', '--side', side])]
    assert [(case['id'], case['status']) for case in result['cases']] == [(case, 'ok') for case in cases]


def test_all_selected_ids_are_refused_before_any_runner_call(monkeypatch):
    monkeypatch.setenv('PATCHTRACE_TIER_R_NO_EVAL', '1')
    calls = []

    def runner(argv, timeout, env):
        calls.append(argv)
        return 0, '{}', None

    with pytest.raises(S.ShardError, match='malformed'):
        S.run_shard(single_shard(['card:zlib-v1-v2', 'aa-card:zlib-v1-v2:old\n']), 0, runner=runner)
    assert calls == []


@pytest.mark.parametrize('field', ['project', 'ref', 'upstream'])
def test_recipe_dependency_cannot_hide_microsoft_source(catalogue, field):
    book = example_recipes()
    dependency = {**copy.deepcopy(book['recipes'][0]), 'project': 'helper'}
    pin = {'project': 'helper', 'ref': 'v1', 'commit': 'a' * 40}
    if field == 'project':
        pin['project'] = dependency['project'] = 'microsoft-helper'
    elif field == 'ref':
        pin['ref'] = 'tier-w-source'
    else:
        dependency['upstream_git'] = 'https://github.com/microsoft/helper.git'
    book['recipes'][0]['depends'] = [pin]
    book['recipes'].append(dependency)
    write_cards(catalogue, CATALOGUE / 'recipes.json', book)
    with pytest.raises(S.ShardError, match='refused'):
        plan_cases(catalogue)


@pytest.mark.parametrize('case_id', ['aa-card:zlib-v1-v2:old', 'noise-card:zlib-v1-v2:new', 'card:zlib-v1-v2'])
@pytest.mark.parametrize(('rc', 'summary', 'reason', 'status'), [
    (1, {'status': 'failed', 'errors': ['source verification failed']}, None, 'failed'),
    (0, {'status': 'failed', 'errors': ['source verification failed']}, None, 'failed'),
    (1, None, None, 'failed'),
    (3, {'status': 'blocked', 'reason': 'tool unavailable'}, None, 'blocked'),
    (0, {'status': 'blocked', 'reason': 'tool unavailable'}, None, 'blocked'),
    (None, None, 'timeout after 7s', 'timeout'),
], ids=['fetch-exit-one', 'failed-summary', 'fetch-without-summary', 'blocked', 'blocked-summary', 'timeout'])
def test_unsuccessful_fetch_stops_before_probe_or_build(case_id, rc, summary, reason, status, monkeypatch):
    monkeypatch.setenv('PATCHTRACE_TIER_R_NO_EVAL', '1')
    commands = []

    def runner(argv, timeout, env):
        commands.append(argv[3:])
        if argv[3] == 'fetch':
            return rc, json.dumps(summary) if summary is not None else '', reason
        return 0, json.dumps({'command': argv[3], 'status': 'ok'}), None

    doc = S.run_shard(single_shard([case_id]), 0, runner=runner, log=lambda text: None)
    assert commands == [['fetch', 'zlib-v1-v2']]
    assert doc['cases'][0]['status'] == status
    _, provenance = S.merge([doc])
    assert provenance['failing_cases'] == [case_id]


@pytest.mark.parametrize('case_id', ['aa-card:zlib-v1-v2:old', 'aa:_template/tiny'])
@pytest.mark.parametrize(('rc', 'summary'), [
    (1, {'command': 'aa', 'status': 'findings', 'not_byte_identical': ['aa-zlib-v1-rebuild']}),
    (0, {'command': 'aa', 'status': 'ok', 'not_byte_identical': ['aa-zlib-v1-rebuild']}),
    (1, {'command': 'aa', 'status': 'findings'}),
    (0, {'command': 'aa', 'status': 'failed', 'error': 'rebuild failed'}),
], ids=['nonidentical-exit-one', 'nonidentical-exit-zero', 'aa-findings', 'failed-summary'])
def test_aa_reproducibility_failures_remain_failed_after_merge(case_id, rc, summary, monkeypatch):
    monkeypatch.setenv('PATCHTRACE_TIER_R_NO_EVAL', '1')

    def runner(argv, timeout, env):
        return (rc, json.dumps(summary), None) if argv[3] == 'aa' else (0, '{}', None)

    doc = S.run_shard(single_shard([case_id]), 0, runner=runner, log=lambda text: None)
    assert doc['cases'][0]['status'] == 'failed'
    if summary.get('not_byte_identical'):
        assert 'not byte-identical' in doc['cases'][0]['reason']
    _, provenance = S.merge([doc])
    assert provenance['failing_cases'] == [case_id]


@pytest.mark.parametrize('failure', ['fetch', 'aa'])
def test_control_failure_reaches_shard_and_merge_cli_exit_status(tmp_path, monkeypatch, capsys, failure):
    monkeypatch.setenv('PATCHTRACE_TIER_R_NO_EVAL', '1')
    case_id = 'aa-card:zlib-v1-v2:new'
    plan_path = tmp_path / 'plan.json'
    plan_path.write_text(json.dumps(single_shard([case_id])), encoding='utf-8')

    def runner(argv, timeout, env):
        if argv[3] == failure:
            summary = ({'status': 'failed', 'errors': ['fetch failed']} if failure == 'fetch' else
                       {'status': 'findings', 'not_byte_identical': ['aa-zlib-v2-rebuild']})
            return 1, json.dumps({'command': failure, **summary}), None
        return 0, '{}', None

    monkeypatch.setattr(S, 'default_runner', runner)
    assert S.main(['run-shard', '--plan', str(plan_path), '--shard', '0', '--out', str(tmp_path / 'shards')]) == S.FINDINGS
    assert json.loads(capsys.readouterr().out)['failed'] == [case_id]
    assert S.main(['merge', '--in', str(tmp_path / 'shards'), '--plan', str(plan_path),
                   '--out', str(tmp_path / 'merge')]) == S.FINDINGS
    assert json.loads(capsys.readouterr().out)['failing_cases'] == 1
    provenance = json.loads((tmp_path / 'merge/tier-r-merge.json').read_text())
    assert provenance['failing_cases'] == [case_id]


@pytest.mark.parametrize('case_id', ['card:zlib-v1-v2', 'suite:_template/tiny'])
def test_ordinary_build_findings_keep_existing_nonfatal_meaning(case_id, monkeypatch):
    monkeypatch.setenv('PATCHTRACE_TIER_R_NO_EVAL', '1')

    def runner(argv, timeout, env):
        if argv[3] == 'fetch':
            return 0, '{"status":"ok"}', None
        return 1, json.dumps({'command': argv[3], 'status': 'findings', 'disagreements': 1}), None

    doc = S.run_shard(single_shard([case_id]), 0, runner=runner)
    assert doc['cases'][0]['status'] == 'findings'
    _, provenance = S.merge([doc])
    assert provenance['failing_cases'] == []
