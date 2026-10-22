"""SPEC-07 §12 analysis profiles: strict model, digest, storage, CLI wiring."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.enrichment import pipeline, profiles
from patchtrace.enrichment.contracts import RankingConfig
from patchtrace.enrichment.profiles import (
    DEFAULT_PROFILE,
    AnalysisProfile,
    ProfileError,
    ProfileStore,
    profile_digest,
)
from patchtrace.service import ProjectService

CUSTOM = {'name': 'triage', 'weights': {'BND': 60, 'INT': 22, 'OVF': 28, 'VAL': 20, 'ERR': 0,
                                        'SIZE': 24, 'WIL': 12, 'SCRUB': 34},
          'enabled': ['BND', 'INT', 'OVF', 'VAL', 'SIZE', 'WIL', 'SCRUB'],
          'feature_ids': None, 'symbol_policy': 'disabled', 'cve_providers': ['nvd'],
          'snapshot_max_age_days': 7, 'cache_dir': None, 'cache_budget_gib': 5}


@pytest.fixture
def project(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    root = service.root
    service.close()
    return root


@pytest.fixture
def store(tmp_path, monkeypatch):
    directory = tmp_path / 'profiles'
    monkeypatch.setattr(profiles, 'default_profiles_dir', lambda: directory)
    return ProfileStore(directory)


def run(args, capsys):
    code = cli.main(args)
    out, err = capsys.readouterr()
    return code, out, err


def test_default_profile_equals_ranking_defaults():
    assert DEFAULT_PROFILE.ranking_config() == RankingConfig()
    assert DEFAULT_PROFILE.feature_filter() is None
    assert DEFAULT_PROFILE.symbol_policy == 'disabled' and not DEFAULT_PROFILE.allow_symbol_downloads


def test_round_trip_through_store(store):
    profile = profiles.build(CUSTOM)
    store.save(profile)
    assert store.get('triage') == profile
    assert profiles.parse(profiles.dumps(profile)) == profile
    assert [p.name for p in store.list()[0]] == ['default', 'triage']
    assert not [p for p in store.directory.iterdir() if p.suffix != '.json']  # no staging leftovers


@pytest.mark.parametrize('change', [
    {'weights': {**CUSTOM['weights'], 'BND': True}},
    {'weights': {**CUSTOM['weights'], 'XYZ': 1}},
    {'weights': {k: v for k, v in CUSTOM['weights'].items() if k != 'BND'}},
    {'weights': {**CUSTOM['weights'], 'BND': 101}},
    {'weights': {**CUSTOM['weights'], 'BND': 1.0}},
    {'enabled': ['BND', 'NOPE']},
    {'enabled': []},
    {'enabled': ['BND', 'BND']},
    {'api_key': 'secret'},
    {'contract': 'profile/2'},
    {'name': ''},
    {'name': 'x' * 65},
    {'name': '../evil'},
    {'name': 'con'},
    {'name': 'trailing.'},
    {'feature_ids': [1, 1]},
    {'feature_ids': [4_294_967_296]},
    {'feature_ids': [True]},
    {'feature_ids': list(range(257))},
    {'symbol_policy': 'cached'},
    {'cve_providers': ['nvd', 'osv']},
    {'snapshot_max_age_days': 0},
    {'snapshot_max_age_days': 3651},
    {'snapshot_max_age_days': '30'},
    {'cache_dir': 'relative/dir'},
    {'cache_budget_gib': 0},
    {'cache_budget_gib': 1025},
])
def test_strict_rejection(change):
    with pytest.raises(ProfileError):
        profiles.parse(json.dumps(CUSTOM | change))


def test_digest_invariant_under_presentation_edits(tmp_path):
    base = profiles.build(CUSTOM)
    edited = profiles.build(CUSTOM | {'name': 'renamed', 'cache_dir': str(tmp_path), 'cache_budget_gib': 99})
    assert profile_digest(base) == profile_digest(edited)
    reordered = profiles.build(CUSTOM | {'enabled': list(reversed(CUSTOM['enabled']))})
    assert profile_digest(reordered) == profile_digest(base)
    assert reordered.ranking_config() == base.ranking_config()
    for change in ({'snapshot_max_age_days': 8}, {'symbol_policy': 'online'}, {'symbol_policy': 'local'}, {'feature_ids': [5]},
                   {'cve_providers': ['nvd', 'msrc']}, {'weights': {**CUSTOM['weights'], 'ERR': 1}}):
        assert profile_digest(profiles.build(CUSTOM | change)) != profile_digest(base)


def test_local_symbol_policy_is_explicit_and_never_enables_network():
    profile = profiles.build(CUSTOM | {'symbol_policy': 'local'})
    assert profile.symbol_policy == 'local' and not profile.allow_symbol_downloads
    assert profile_digest(profile) != profile_digest(profiles.build(CUSTOM))
    schema = json.loads((Path(__file__).parents[1] / 'docs/schemas/profile/AnalysisProfile.json').read_text())
    assert schema['properties']['symbol_policy']['enum'] == ['disabled', 'local', 'online']


def test_store_rules(store, tmp_path):
    with pytest.raises(ProfileError, match='read-only'):
        store.save(DEFAULT_PROFILE)
    with pytest.raises(ProfileError):
        store.delete('default')
    store.save(profiles.build(CUSTOM))
    with pytest.raises(ProfileError, match='exists'):
        store.save(profiles.build(CUSTOM | {'name': 'TRIAGE'}))
    store.save(profiles.build(CUSTOM | {'name': 'renamed'}), replaces='triage')
    assert store.names() == ['renamed']
    (store.directory / 'broken.json').write_text('{"contract":"profile/1","name":"broken","extra":1}')
    (store.directory / 'liar.json').write_text(profiles.dumps(profiles.build(CUSTOM | {'name': 'other'})))
    valid, errors = store.list()
    assert [p.name for p in valid] == ['default', 'renamed'] and len(errors) == 2
    store.delete('renamed')
    assert store.names() == ['broken', 'liar']


def test_persisted_file_has_no_secret_fields(store):
    store.save(profiles.build(CUSTOM))
    data = json.loads((store.directory / 'triage.json').read_text())
    assert set(data) == {'contract', 'name', 'weights', 'enabled', 'feature_ids', 'symbol_policy',
                         'cve_providers', 'snapshot_max_age_days', 'cache_dir', 'cache_budget_gib'}
    assert not any('key' in k or 'token' in k or 'secret' in k for k in data)


def test_wil_stage_id_matches_pipeline(project):
    service = ProjectService.open(project)
    try:
        for ids in (None, frozenset({3, 1})):
            result = pipeline.run(service.project, pipeline.PipelineOptions(feature_ids=ids))
            assert pipeline.wil_stage_id(result.guard.input_digest, ids) == result.stage_ids['wil']
    finally:
        service.close()


def test_cli_profile_by_name_and_file_agree_and_load_profile(project, store, capsys, tmp_path):
    from patchtrace.enrichment.ranking import config_digest
    from patchtrace.enrichment.storage import EnrichmentStore
    profile = profiles.build(CUSTOM)
    store.save(profile)
    file = tmp_path / 'p.json'
    file.write_text(profiles.dumps(profile))
    code, out, _ = run(['rank', str(project), '--json', '--dry-run', '--profile', str(file)], capsys)
    by_file = json.loads(out)['result']
    code2, out2, _ = run(['rank', str(project), '--json', '--profile', 'triage'], capsys)
    by_name = json.loads(out2)['result']
    assert code == code2 == 0
    assert by_file == by_name
    assert by_name['profile'] == {'name': 'triage', 'digest': profile_digest(profile)}
    assert by_name['config_digest'] == config_digest(profile.ranking_config()) != config_digest(RankingConfig())
    service = ProjectService.open(project)
    try:
        enrichment = EnrichmentStore(service.store)
        assert pipeline.load_default(enrichment, service.project)[0] is None
        loaded, sets, note = pipeline.load_profile(enrichment, service.project, by_name['config_digest'])
        assert note == '' and sets
        assert {e.match_id: e.score for e in loaded.entries} == {e['match_id']: e['score'] for e in by_name['entries']}
        # Same weights but a different feature filter is a different stored ranking.
        assert pipeline.load_profile(enrichment, service.project, by_name['config_digest'], frozenset({7}))[0] is None
    finally:
        service.close()


@pytest.mark.parametrize('extra', [['--weights', 'w.json'], ['--disable', 'ERR']])
def test_cli_profile_conflicts_exit_2(project, store, capsys, extra):
    assert run(['rank', str(project), '--dry-run', '--profile', 'default', *extra], capsys)[0] == 2


def test_cli_profile_errors_exit_2(project, store, capsys, tmp_path):
    assert run(['rank', str(project), '--dry-run', '--profile', 'missing'], capsys)[0] == 2
    bad = tmp_path / 'bad.json'
    bad.write_text(json.dumps(CUSTOM | {'enabled': []}))
    assert run(['rank', str(project), '--dry-run', '--profile', str(bad)], capsys)[0] == 2
    assert run(['flags', str(project), '--dry-run', '--profile', 'default', '--feature-id', '1'], capsys)[0] == 2


def test_cli_default_profile_matches_no_profile(project, store, capsys):
    plain = json.loads(run(['rank', str(project), '--json', '--dry-run'], capsys)[1])['result']
    named = json.loads(run(['rank', str(project), '--json', '--dry-run', '--profile', 'default'], capsys)[1])['result']
    assert plain['entries'] == named['entries'] and plain['config_digest'] == named['config_digest']
    assert named['profile']['digest'] == profile_digest(DEFAULT_PROFILE)


def test_cli_profile_cache_dir_default(project, store, capsys, tmp_path):
    cache = tmp_path / 'cache'
    store.save(profiles.build(CUSTOM | {'cache_dir': str(cache)}))
    assert run(['rank', str(project), '--dry-run', '--profile', 'triage'], capsys)[0] == 0
    assert (cache / 'v1').is_dir()


def test_cli_correlate_uses_profile_max_age(project, store, capsys, tmp_path, monkeypatch):
    seen = {}
    real = pipeline.run

    def spy(project, options=None, *a, **k):
        seen['options'] = options
        return real(project, options, *a, **k)
    monkeypatch.setattr(pipeline, 'run', spy)
    store.save(profiles.build(CUSTOM))
    run(['correlate', str(project), '--cve', 'CVE-2024-38063', '--dry-run', '--profile', 'triage'], capsys)
    assert seen['options'].max_age_days == 7
    assert seen['options'].config == profiles.build(CUSTOM).ranking_config()


def test_profile_model_is_frozen():
    with pytest.raises(ValueError):
        DEFAULT_PROFILE.name = 'x'  # type: ignore[misc]
    assert isinstance(DEFAULT_PROFILE, AnalysisProfile)


def test_profile_store_rejects_path_traversal_names(tmp_path):
    from patchtrace.enrichment.profiles import ProfileError, ProfileStore
    victim = tmp_path / 'victim.json'
    victim.write_text('{}')
    store = ProfileStore(tmp_path / 'profiles')
    for bad in ('../victim', 'a/b', '..', 'x\n'):
        with pytest.raises(ProfileError):
            store.delete(bad)
    assert victim.exists()
