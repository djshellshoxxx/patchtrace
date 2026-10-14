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
