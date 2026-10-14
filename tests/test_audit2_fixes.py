"""Second-audit regression tests (items 3-13)."""
import pytest

from patchtrace.backend import BackendConfig, _passthrough_error, build_child_env


def _cfg(tmp_path, **kw):
    return BackendConfig('/py', str(tmp_path), **kw)


def test_restricted_env_keeps_inherited_java_home(tmp_path):
    base = {'PATH': '/usr/bin', 'JAVA_HOME': '/opt/jdk', 'JDK_HOME': '/opt/jdk2', 'GITHUB_TOKEN': 'x'}
    env = build_child_env(base, _cfg(tmp_path), None, symbol_downloads=False, for_tool='ghidra', windows=False)
    assert env['JAVA_HOME'] == '/opt/jdk' and env['JDK_HOME'] == '/opt/jdk2' and 'GITHUB_TOKEN' not in env
    win = build_child_env({'Path': 'x', 'java_home': 'C:/jdk'}, _cfg(tmp_path), None, symbol_downloads=False,
                          for_tool='ghidra', windows=True)
    assert win['java_home'] == 'C:/jdk'
    rizin = build_child_env(base, _cfg(tmp_path), None, symbol_downloads=False, for_tool='rizin', windows=False)
    assert 'JAVA_HOME' not in rizin


@pytest.mark.parametrize('name', ['PYTHONSTARTUP', 'PYTHONBREAKPOINT', 'pythonwarnings', 'LD_AUDIT',
                                  'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'BASH_ENV', 'ENV'])
def test_passthrough_denylist(name):
    assert _passthrough_error(name)


def test_passthrough_allows_ordinary_names():
    assert not _passthrough_error('HTTPS_PROXY') and not _passthrough_error('ENVIRONMENT_X')


def test_stage_version_bump_makes_stored_pipeline_stale(tmp_path):
    from patchtrace.enrichment import pipeline
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.sample import create_sample
    svc = create_sample(tmp_path / 'p')
    store = EnrichmentStore(svc.store)
    orig = dict(pipeline.STAGE_VERSIONS)
    try:
        pipeline.STAGE_VERSIONS.update({k: 1 for k in orig})
        res1 = pipeline.run(svc.project, pipeline.PipelineOptions())
        pipeline.publish(store, svc.project, res1)
        assert pipeline.load_default(store, svc.project)[0] is not None  # same version still served
    finally:
        pipeline.STAGE_VERSIONS.update(orig)
    ranking, sets, note = pipeline.load_default(store, svc.project)
    assert ranking is None and sets == () and 'stale' in note
    from patchtrace.enrichment import ranking as rk
    profile = pipeline.load_profile(store, svc.project, rk.config_digest(rk.RankingConfig()))
    assert profile[0] is None


# --- secondary store / enrichment storage (items 5, 6, 8) ------------------------------------------

def _case(tmp_path):
    from patchtrace.enrichment.storage import EnrichmentStore, Guard
    from patchtrace.sample import create_sample
    svc = create_sample(tmp_path / 'p')
    return svc, EnrichmentStore(svc.store), Guard(svc.project.id, 'r', 'a' * 64, 'b' * 64)


def _run(run_id, engine='rz-diff', status='failed', older='a' * 64, newer='b' * 64, match_set_id=None,
         output=None, created='t'):
    from patchtrace.secondary.runs import EngineRun
    return EngineRun(run_id=run_id, engine=engine, engine_version='0.9.1', executable_path_sha256=None,
                     argv_digest='a' * 64, older_sha256=older, newer_sha256=newer, orientation='older->newer',
                     cache_key='c' * 64, status=status, error_code=None, returncode=0, started_utc=created,
                     duration_ms=1, stderr_tail='', output_sha256=output, match_set_id=match_set_id)


def test_cache_snapshot_corrupt_run_row_is_a_miss(tmp_path):
    from patchtrace.secondary.store import cache_snapshot, publish_run
    svc, store, g = _case(tmp_path)
    publish_run(store, g, g, 1, _run('x1'))
    svc.store.connection.execute("update enrichment_entries set body='{}' where id='x1'")
    svc.store.connection.commit()
    assert cache_snapshot(store, 'a' * 64, 'b' * 64) == {}


def _match_set(sha='1' * 64, run_id=None):
    from patchtrace.secondary.contracts import SecondaryMatch, SecondaryMatchSet
    from patchtrace.secondary.runs import as_v2
    m = SecondaryMatch(engine='rz-diff', engine_version='0.9.1', older_address=1, newer_address=1,
                       older_name=None, newer_name=None, similarity_milli=500, similarity_text='0.5',
                       confidence_milli=None, confidence_text=None, flags=(), algorithm='levenshtein-bytes')
    s = SecondaryMatchSet(engine='rz-diff', engine_version='0.9.1', older_sha256='a' * 64, newer_sha256='b' * 64,
                          file_sha256=sha, matches=(m,), limitations=('raw bytes',))
    return as_v2(s, run_id)


def test_load_secondary_isolates_bad_rows(tmp_path, caplog):
    import hashlib

    from patchtrace.secondary import load_secondary
    from patchtrace.secondary.store import publish_engine_set
    svc, store, g = _case(tmp_path)
    good = publish_engine_set(store, g, g, 1, _match_set('2' * 64))
    body = '{"contract":"secondary/9"}'
    db = svc.store.connection
    db.execute("insert into enrichment_entries values('secondary-matches:bad','secondary-matches',?,1,'r',?,?,"
               "'complete',0,'2026',?,?)", (g.project_id, g.raw_sha256, g.input_digest, body,
                                            hashlib.sha256(body.encode()).hexdigest()))
    db.execute("insert into enrichment_entries values('secondary-matches:corrupt','secondary-matches',?,1,'r',?,?,"
               "'complete',0,'2026','{}','00')", (g.project_id, g.raw_sha256, g.input_digest))
    db.commit()
    with caplog.at_level('WARNING'):
        rows = load_secondary(store)
    assert [e.id for e, _ in rows] == [good.id]
    assert 'secondary-matches:bad' in caplog.text and 'secondary-matches:corrupt' in caplog.text


def test_extension_version_two_is_stamped_only_for_secondary_v2_and_runs(tmp_path):
    from patchtrace.enrichment import storage
    from patchtrace.secondary.store import publish_run
    assert storage.EXTENSION_VERSION == 2
    svc, store, g = _case(tmp_path)
    store.ensure()

    def version():
        return svc.store.connection.execute(
            "select value from enrichment_meta where key='extension_version'").fetchone()[0]
    assert version() == '1' and not store.read_only
    store.publish('signals', g, g, 1, 'complete', {'items': []}, 'signals:a')
    assert version() == '1'  # v1 clients keep full access until a v2-only row is written
    publish_run(store, g, g, 1, _run('r1'))
    assert version() == '2'
    again = storage.EnrichmentStore(svc.store)
    again.ensure()
    assert not again.read_only
    svc.store.connection.execute("update enrichment_meta set value='3' where key='extension_version'")
    svc.store.connection.commit()
    newer = storage.EnrichmentStore(svc.store)
    newer.ensure()
    assert newer.read_only


def test_engine_run_rows_are_pruned_per_pair_but_sets_and_referenced_runs_survive(tmp_path):
    from patchtrace.enrichment import storage
    from patchtrace.secondary.store import publish_engine_set, publish_run
    svc, store, g = _case(tmp_path)
    ms = publish_engine_set(store, g, g, 1, _match_set('1' * 64, run_id='keepme'))
    publish_run(store, g, g, 1, _run('keepme', status='ok', match_set_id=ms.id, output='1' * 64))
    for n in range(storage.RUN_KEEP + 5):
        publish_run(store, g, g, 1, _run(f'r{n:02d}'))
    for n in range(3):
        publish_run(store, g, g, 1, _run(f'o{n}', engine='bindiff', older='c' * 64))
    ids = {e.id for e in store.entries('engine-run')}
    failed = sorted(i for i in ids if i.startswith('r'))
    assert len(failed) <= storage.RUN_KEEP and failed[-1] == f'r{storage.RUN_KEEP + 4:02d}'
    assert 'keepme' in ids and {'o0', 'o1', 'o2'} <= ids
    assert [e.id for e in store.entries('secondary-matches')] == [ms.id]


def test_make_room_can_evict_engine_runs(tmp_path, monkeypatch):
    from patchtrace.enrichment import storage
    from patchtrace.secondary.store import publish_run
    svc, store, g = _case(tmp_path)
    monkeypatch.setattr(storage, 'RUN_KEEP', 100)
    for n in range(4):
        publish_run(store, g, g, 1, _run(f'r{n}'))
    freed = store.make_room(1, g)
    assert freed >= 1 and len(store.entries('engine-run')) == 3  # only as much as needed, oldest first
    assert 'r0' not in {e.id for e in store.entries('engine-run')}


# --- secondary run CLI (items 6, 13) --------------------------------------------------------------

def _cli_project(tmp_path):
    from patchtrace.service import ProjectService
    service = ProjectService.sample(tmp_path / 'case')
    root = service.root
    service.close()
    return root


def _cli(root, exe, capsys):
    import json

    from patchtrace import cli
    code = cli.main(['secondary', 'run', str(root), '--json', '--rz-diff', exe, '--engine', 'rz-diff',
                     '--no-cache'])
    return code, json.loads(capsys.readouterr().out)


def test_adapter_parse_input_error_is_runtime_exit_3(tmp_path, capsys):
    from fake_exe import make_fake_exe
    source = ("import sys\nif sys.argv[1:] == ['-v']:\n    print('rz-diff 0.9.1')\n    sys.exit(0)\n"
              "print('this is not json')\n")
    exe = str(make_fake_exe(tmp_path / 'bin', 'rz-diff', source))
    code, doc = _cli(_cli_project(tmp_path), exe, capsys)
    assert doc['result']['runs'][0]['error_code'] == 'PT-SECONDARY-INPUT'
    assert code == 3


def test_persistence_failure_is_recorded_not_fatal(tmp_path, capsys, monkeypatch):
    from test_cli_secondary_run import fake_rz

    from patchtrace.enrichment.contracts import EnrichmentError
    from patchtrace.secondary import cli_run

    def boom(*args, **kwargs):
        raise EnrichmentError('PT-ENRICH-LIMIT', 'enrichment result exceeds 32 MiB row limit')
    monkeypatch.setattr(cli_run, 'publish_engine_set', boom)
    root = _cli_project(tmp_path)
    code, doc = _cli(root, fake_rz(tmp_path), capsys)
    [row] = doc['result']['runs']
    assert row['status'] == 'failed' and row['error_code'] == 'PT-ENRICH-LIMIT' and row['matches'] == 0
    assert code == 3 and any('PT-ENRICH-LIMIT' in w for w in doc['warnings'])
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.service import ProjectService
    service = ProjectService.open(root)
    try:
        [stored] = EnrichmentStore(service.store).entries('engine-run')
        assert stored.body['status'] == 'failed' and stored.body['error_code'] == 'PT-ENRICH-LIMIT'
    finally:
        service.close()


def test_run_record_failure_too_is_only_a_warning(tmp_path, capsys, monkeypatch):
    from test_cli_secondary_run import fake_rz

    from patchtrace.enrichment.contracts import EnrichmentError
    from patchtrace.secondary import cli_run

    def boom(*args, **kwargs):
        raise EnrichmentError('PT-ENRICH-LIMIT', 'cap')
    monkeypatch.setattr(cli_run, 'publish_engine_set', boom)
    monkeypatch.setattr(cli_run, 'publish_run', boom)
    code, doc = _cli(_cli_project(tmp_path), fake_rz(tmp_path), capsys)
    assert code == 3 and doc['result']['runs'][0]['status'] == 'failed'


def test_empty_nvd_key_env_is_no_key(monkeypatch):
    from patchtrace import cli
    monkeypatch.setenv('NVD_EMPTY', '')
    monkeypatch.setenv('NVD_BLANK', '  \n')
    monkeypatch.setenv('NVD_REAL', ' abc123 ')
    monkeypatch.delenv('NVD_MISSING', raising=False)
    assert [cli._api_key(n) for n in ('', 'NVD_EMPTY', 'NVD_BLANK', 'NVD_MISSING')] == [None] * 4
    assert cli._api_key('NVD_REAL') == 'abc123'
