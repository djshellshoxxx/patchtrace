"""SPEC-05 section 4.3 / 6.5 shared configuration tests (T-C01..T-C06) and CliRunReport contract."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace import config as cfgmod
from patchtrace.config import (
    CONFIG_KEYS,
    ConfigError,
    PatchTraceConfig,
    default_config_path,
    get_key,
    load_config,
    migrate_qsettings,
    parse_base_address,
    render_name_template,
    resolve,
    save_config,
    set_key,
    unset_key,
)
from patchtrace.models import EXIT_CODES, BackendCapabilities, CliRunReport

ROOT = Path(__file__).resolve().parents[1]
BACKEND_KEYS = {'python_executable', 'ghidra_dir', 'timeout_seconds', 'java_home', 'workspace', 'work_root',
                'ghidra_project_location', 'ghidra_project_name', 'gzfs_path', 'keep_ghidra_project',
                'keep_workspace'}
GHIDRIFF_KEYS = {'engine', 'threaded', 'force_analysis', 'force_diff', 'symbols', 'symbols_path', 'min_func_len',
                 'max_ram_percent', 'bsim', 'bsim_full', 'decompiler_timeout', 'use_calling_counts',
                 'base_address', 'program_options', 'gdt', 'verbose_analysis', 'jvm_args', 'max_section_funcs'}
SPEC_EXAMPLE = {
    "schema_version": 1,
    "backend": {
        "python_executable": None, "ghidra_install_dir": None, "java_home": None,
        "timeout_seconds": 3600, "workspace": "local", "work_root": None,
        "ghidra_project_location": None, "ghidra_project_name": "pt", "gzfs_path": None},
    "analysis": {
        "engine": "version-tracking", "threaded": True, "force_analysis": False, "force_diff": False,
        "symbols": True, "symbols_path": None, "min_func_len": 10, "max_ram_percent": 60.0,
        "bsim": True, "bsim_full": False, "decompiler_timeout": 60, "use_calling_counts": False,
        "base_address": None, "program_options": None, "gdt": [], "verbose_analysis": False,
        "jvm_args": [], "max_section_funcs": 200},
    "output": {
        "directory": None, "emit": ["ghidriff-md", "ghidriff-json", "report-md", "summary", "metadata"],
        "name_template": "{old}-{new}", "report_include_code": False, "report_include_notes": True,
        "keep_ghidra_project": False, "keep_workspace": False},
    "logging": {"console_level": "info", "file_level": "debug", "format": "text",
                "engine_level": "INFO", "engine_file_level": "INFO"},
    "provider": {"kind": "ollama", "endpoint": "http://127.0.0.1:11434", "model": "", "context_budget": 24000},
    "desktop": {"font_size": 11, "sync_scroll": True},
    "extensions": {},
}


def write(path, text):
    path.write_text(text, encoding='utf-8')
    return path


def test_defaults_equal_spec_example_and_round_trip(tmp_path):
    """T-C01: init -> show equals the defaults."""
    assert PatchTraceConfig().model_dump(mode='json') == SPEC_EXAMPLE
    path = save_config(PatchTraceConfig(), tmp_path / 'nested' / 'config.json')
    assert json.loads(path.read_text(encoding='utf-8')) == SPEC_EXAMPLE
    assert load_config(path) == PatchTraceConfig()
    assert [p.name for p in path.parent.iterdir()] == ['config.json']  # no temp leftovers


@pytest.mark.parametrize('key,text,expected', [
    ('backend.timeout_seconds', '7200', 7200),
    ('analysis.max_ram_percent', '80', 80.0),
    ('analysis.bsim', 'false', False),
    ('analysis.threaded', 'no', False),
    ('analysis.engine', 'SimpleDiff', 'simple'),
    ('analysis.gdt', 'a.gdt,b.gdt', ['a.gdt', 'b.gdt']),
    ('analysis.jvm_args', '["-Xss8m"]', ['-Xss8m']),
    ('analysis.base_address', '0x140000000', '0x140000000'),
    ('backend.ghidra_project_name', '123', '123'),
    ('backend.python_executable', 'C:\\Py\\python.exe', 'C:\\Py\\python.exe'),
    ('output.emit', 'summary', ['summary']),
    ('logging.engine_level', 'DEBUG', 'DEBUG'),
    ('provider.model', 'qwen', 'qwen'),
    ('desktop.sync_scroll', 'off', False),
])
def test_set_get_unset_per_type(key, text, expected):
    """T-C01: typed set/get/unset."""
    changed = set_key(PatchTraceConfig(), key, text)
    assert get_key(changed, key) == expected
    restored = unset_key(changed, key)
    assert get_key(restored, key) == get_key(PatchTraceConfig(), key)


@pytest.mark.parametrize('key,text', [
    ('analysis.max_ram_percent', '0'), ('analysis.max_ram_percent', '95.5'),
    ('backend.timeout_seconds', '0'), ('backend.timeout_seconds', '604801'),
    ('backend.ghidra_project_name', 'bad name'), ('backend.ghidra_project_name', 'x' * 33),
    ('analysis.engine', 'fast'), ('output.emit', 'summary,bogus'), ('output.emit', 'all,summary'),
    ('output.name_template', '.{old}'), ('output.name_template', '{old}/{new}'),
    ('output.name_template', '{nope}'), ('logging.console_level', 'verbose'),
    ('analysis.base_address', '0x1' + '0' * 16), ('analysis.base_address', 'zz'),
    ('analysis.min_func_len', '-1'), ('nonexistent.key', '1'),
])
def test_invalid_set_raises_and_file_unchanged(tmp_path, key, text):
    """T-C01: invalid value -> PT-CONFIG and the file is unchanged."""
    path = save_config(PatchTraceConfig(), tmp_path / 'config.json')
    before = path.read_bytes()
    with pytest.raises(ConfigError, match='^PT-CONFIG:'):
        save_config(set_key(load_config(path), key, text), path)
    assert path.read_bytes() == before


@pytest.mark.parametrize('text', [
    '{"schema_version": 1, "surprise": {}}',
    '{"schema_version": 1, "backend": {"timeout_seconds": 10, "timeout_seconds": 20}}',
    '{"schema_version": 2}',
    '{"backend": {}}',
    '{"schema_version": 1, "analysis": {"max_ram_percent": NaN}}',
    '{"schema_version": 1, "analysis": {"max_ram_percent": Infinity}}',
    '{"schema_version": 1, "backend": {"api_key": "x"}}',
    '{"schema_version": 1, "analysis": {"bsim": "true"}}',
    '{"schema_version": 1, "extensions": {"rank": {"token": "x"}}}',
    '[1]', '{not json', '',
])
def test_strict_loading_rejects_with_pt_config(tmp_path, text):
    """T-C02: unknown key, duplicate key, future version, NaN -> PT-CONFIG."""
    with pytest.raises(ConfigError, match='^PT-CONFIG:'):
        load_config(write(tmp_path / 'c.json', text))


def test_missing_and_non_utf8_file(tmp_path):
    with pytest.raises(ConfigError, match='^PT-CONFIG: config file not found'):
        load_config(tmp_path / 'absent.json')
    (tmp_path / 'bad.json').write_bytes(b'{"schema_version": 1, "provider": {"model": "\xff"}}')
    with pytest.raises(ConfigError, match='^PT-CONFIG:'):
        load_config(tmp_path / 'bad.json')
    with pytest.raises(ConfigError):
        resolve(tmp_path / 'absent.json', env={})


def test_default_config_path_locations(tmp_path):
    assert default_config_path({'PATCHTRACE_CONFIG': 'X:/c.json'}) == Path('X:/c.json')
    assert default_config_path({'APPDATA': 'C:\\Users\\me\\AppData\\Roaming'}, platform='win32') == \
        Path('C:\\Users\\me\\AppData\\Roaming') / 'PatchTrace' / 'config.json'
    assert default_config_path({'XDG_CONFIG_HOME': str(tmp_path)}, platform='linux') == \
        tmp_path / 'patchtrace' / 'config.json'
    assert default_config_path({}, platform='linux') == Path.home() / '.config' / 'patchtrace' / 'config.json'


LAYERS = ['default', 'env-generic', 'file', 'env', 'flag']


@pytest.mark.parametrize('top', range(len(LAYERS)))
@pytest.mark.parametrize('key,env_generic,env_pt', [
    ('backend.ghidra_install_dir', 'GHIDRA_INSTALL_DIR', None),
    ('backend.java_home', 'JAVA_HOME', None),
    ('backend.python_executable', None, 'PATCHTRACE_PYTHON'),
    ('backend.work_root', None, 'PATCHTRACE_WORK_ROOT'),
])
def test_precedence_matrix(tmp_path, top, key, env_generic, env_pt):
    """T-C03: each layer overrides the one below; origins report the winner."""
    env, overrides, file_path = {}, {}, None
    layers = LAYERS[1:top + 1]
    if 'env-generic' in layers and env_generic:
        env[env_generic] = '/layer/env-generic'
    if 'file' in layers:
        file_path = save_config(set_key(PatchTraceConfig(), key, '/layer/file'), tmp_path / 'c.json')
    if 'env' in layers and env_pt:
        env[env_pt] = '/layer/env'
    if 'flag' in layers:
        overrides[key] = '/layer/flag'
    effective = resolve(file_path, use_file=file_path is not None, env=env, overrides=overrides)
    winner = next((layer for layer in reversed(['default', *layers])
                   if layer in ('default', 'file', 'flag')
                   or (layer == 'env-generic' and env_generic) or (layer == 'env' and env_pt)), 'default')
    assert effective.origins[key] == winner == effective.origin(key)
    assert effective.get(key) == (None if winner == 'default' else f'/layer/{winner}')


def test_null_in_file_does_not_mask_env_and_no_config(tmp_path, monkeypatch):
    path = save_config(PatchTraceConfig(), tmp_path / 'c.json')
    effective = resolve(path, env={'GHIDRA_INSTALL_DIR': '/g'})
    assert effective.get('backend.ghidra_install_dir') == '/g'
    assert effective.origins['backend.ghidra_install_dir'] == 'env-generic'
    assert effective.origins['backend.timeout_seconds'] == 'file'
    assert set(effective.origins) == set(CONFIG_KEYS)
    # default location used only when present; --no-config ignores it.
    save_config(set_key(PatchTraceConfig(), 'analysis.bsim', 'false'), tmp_path / 'default.json')
    env = {'PATCHTRACE_CONFIG': str(tmp_path / 'default.json')}
    assert resolve(env=env).get('analysis.bsim') is False
    assert resolve(use_file=False, env=env).get('analysis.bsim') is True
    assert resolve(env={'PATCHTRACE_CONFIG': str(tmp_path / 'none.json')}).path is None


def test_flag_overrides_typed_and_rejected():
    effective = resolve(use_file=False, env={}, overrides={
        'analysis.bsim': False, 'analysis.max_ram_percent': '75', 'analysis.gdt': ('a.gdt',),
        'analysis.engine': 'StructuralGraphDiff', 'analysis.base_address': '4096', 'output.directory': None})
    assert effective.origins['analysis.bsim'] == 'flag' and effective.origins['output.directory'] == 'default'
    kwargs = effective.ghidriff_kwargs()
    assert kwargs['bsim'] is False and kwargs['max_ram_percent'] == 75.0 and kwargs['gdt'] == ('a.gdt',)
    assert kwargs['engine'] == 'structural-graph' and kwargs['base_address'] == 4096
    with pytest.raises(ConfigError, match='analysis.decompiler_timeout'):
        resolve(use_file=False, env={}, overrides={'analysis.decompiler_timeout': 0})
    with pytest.raises(ConfigError, match='unknown configuration key'):
        resolve(use_file=False, env={}, overrides={'input': 'x.sys'})


def test_kwargs_have_exact_keys_and_types():
    effective = resolve(use_file=False, env={}, overrides={'analysis.base_address': '0x140000000',
                                                            'analysis.jvm_args': '-Xmx8g'})
    backend, ghidriff = effective.backend_kwargs(), effective.ghidriff_kwargs()
    assert set(backend) == BACKEND_KEYS and set(ghidriff) == GHIDRIFF_KEYS
    assert backend['python_executable'] == '' and backend['ghidra_dir'] == '' and backend['java_home'] is None
    assert ghidriff['base_address'] == 0x140000000 and ghidriff['jvm_args'] == ('-Xmx8g',)
    assert isinstance(ghidriff['gdt'], tuple)
    assert parse_base_address('18446744073709551615') == 2**64 - 1
    assert parse_base_address(str(2**64)) is None


def test_save_excludes_per_run_keys_and_reproduces(tmp_path):
    """T-C04: saved effective config holds no inputs/out/project and reproduces the same options."""
    effective = resolve(use_file=False, env={'GHIDRA_INSTALL_DIR': '/g', 'PATCHTRACE_PYTHON': '/py'},
                        overrides={'analysis.bsim': 'false', 'analysis.jvm_args': ['-Xss8m'],
                                   'backend.timeout_seconds': 99})
    path = save_config(effective.config, tmp_path / 'saved.json')
    saved = json.loads(path.read_text(encoding='utf-8'))
    flat = json.dumps(saved)
    for forbidden in ('"old"', '"new"', '"inputs"', '"project"', '"out"', '"argv"'):
        assert forbidden not in flat
    assert saved['output']['directory'] is None
    again = resolve(path, env={})
    assert again.ghidriff_kwargs() == effective.ghidriff_kwargs()
    assert again.backend_kwargs() == effective.backend_kwargs()


def test_saved_config_contains_no_secret_like_keys(tmp_path):
    """T-C05 (config part): the model has no credential field, so nothing secret can be saved."""
    secret = re.compile(r'(api[_-]?key|token|secret|password|credential|authorization)', re.IGNORECASE)
    assert not [k for k in CONFIG_KEYS if secret.search(k)]
    config = migrate_qsettings({'provider/kind': 'openai', 'provider/endpoint': 'https://api.example.com/v1',
                                'provider/api_key': 'sk-should-never-persist', 'provider/model': 'm'})
    text = save_config(config, tmp_path / 'c.json').read_text(encoding='utf-8')
    assert 'sk-should-never-persist' not in text
    keys = re.findall(r'"([^"]+)":', text)
    assert not [k for k in keys if secret.search(k)]
    with pytest.raises(ValidationError):
        PatchTraceConfig.model_validate({'provider': {'api_key': 'x'}})
    with pytest.raises(ValidationError):
        PatchTraceConfig(extensions={'cve': {'nested': {'Authorization': 'x'}}})


QSETTINGS_FIXTURE = {  # values as QSettings returns them from an INI file (strings) plus native types
    'backend/python': 'C:\\Py\\python.exe', 'backend/ghidra': 'C:\\Tools\\ghidra_12.0.4_PUBLIC',
    'backend/timeout': '7200', 'provider/kind': 'openai', 'provider/endpoint': 'https://api.example.com/v1',
    'provider/model': 'gpt-x', 'provider/context_budget': 32000, 'desktop/font_size': '14',
    'desktop/sync': 'false', 'desktop/geometry': b'\x01\xd9\xd0\xcb', 'desktop/main': b'\x00\xff',
    'recent/projects': ['C:\\cases\\one'], 'recent/project': 'C:\\cases\\one',
}


def test_qsettings_migration_and_idempotence():
    """T-C06: mapped keys are carried, geometry is not, and the result is idempotent."""
    migrated = migrate_qsettings(QSETTINGS_FIXTURE)
    assert migrated.backend.python_executable == 'C:\\Py\\python.exe'
    assert migrated.backend.ghidra_install_dir == 'C:\\Tools\\ghidra_12.0.4_PUBLIC'
    assert migrated.backend.timeout_seconds == 7200
    assert (migrated.provider.kind, migrated.provider.endpoint, migrated.provider.model,
            migrated.provider.context_budget) == ('openai', 'https://api.example.com/v1', 'gpt-x', 32000)
    assert migrated.desktop.font_size == 14 and migrated.desktop.sync_scroll is False
    text = json.dumps(migrated.model_dump(mode='json'))
    assert 'geometry' not in text and 'cases' not in text
    assert migrate_qsettings(QSETTINGS_FIXTURE, migrated) == migrated
    assert migrate_qsettings(QSETTINGS_FIXTURE) == migrated
    assert migrate_qsettings({}) == PatchTraceConfig()


def test_qsettings_migration_skips_empty_and_invalid():
    migrated = migrate_qsettings({'backend/python': '', 'backend/timeout': 'abc', 'desktop/font_size': '99',
                                  'provider/kind': 'unknown', 'desktop/sync': True})
    assert migrated == PatchTraceConfig()


def test_name_template_render():
    assert render_name_template('{old}-{new}', old='a', new='b') == 'a-b'
    with pytest.raises(ValueError):
        render_name_template('{old}', old='.hidden')
    with pytest.raises(ValueError):
        render_name_template('{old}', old='x' * 97)
    with pytest.raises(ValueError):
        render_name_template('{old}-{new}', old='a')


def test_config_module_has_no_qt_import():
    code = ('import sys, patchtrace.config, patchtrace.models; '
            'assert not [m for m in sys.modules if m.startswith("PySide6")]')
    subprocess.run([sys.executable, '-c', code], check=True, env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')})
    assert cfgmod.ENGINE_CLASSES['structural-graph'] == 'StructualGraphDiff'


def report(**changes):
    data = {'tool': {'version': '0.1.0'}, 'command': 'diff', 'started': '2026-10-11T12:00:00Z',
            'exit_code': 0, 'exit_name': 'OK', 'status': 'completed'}
    data.update(changes)
    return CliRunReport.model_validate(data)


def test_cli_run_report_contract():
    assert report().schema_version == 1
    full = report(warnings=[{'code': 'GP-ONEDRIVE', 'message': 'm', 'path': 'p'}],
                  inputs=[{'side': 'older', 'path': 'a', 'name': 'a', 'sha256': 'a' * 64, 'size': 1}],
                  ghidriff={'argv': ['py'], 'cwd': '/g', 'argv_sha256': 'b' * 64,
                            'capabilities': {'engines': ['SimpleDiff'], 'probed': True}},
                  settings={'engine': 'VersionTrackingDiff', 'origins': {'analysis.bsim': 'flag'}},
                  results={'counts': {'modified': 1, 'added': 0, 'deleted': 0}},
                  artifacts=[{'kind': 'summary', 'path': 'x.summary.json', 'sha256': 'c' * 64, 'size': 2}])
    assert CliRunReport.model_validate(json.loads(full.model_dump_json())) == full
    failed = report(exit_code=2, exit_name='ENVIRONMENT', status='failed',
                    error={'code': 'GP-DOT', 'taxonomy': 'PT-BACKEND', 'message': 'dot', 'hint': 'h'})
    assert failed.error.code == 'GP-DOT'
    for bad in [dict(exit_code=3), dict(exit_name='BOGUS'), dict(schema_version=2), dict(status='done'),
                dict(extra=1), dict(status='failed', exit_code=3, exit_name='ANALYSIS_FAILED'),
                dict(settings={'engine': 'x', 'origins': {'k': 'cli'}}),
                dict(inputs=[{'side': 'older', 'path': 'a', 'name': 'a', 'sha256': 'guess', 'size': 1}])]:
        with pytest.raises(ValidationError):
            report(**bad)


def test_exit_codes_table():
    assert EXIT_CODES == {'OK': 0, 'INTERNAL': 1, 'ENVIRONMENT': 2, 'ANALYSIS_FAILED': 3, 'NO_DIFFERENCES': 4,
                          'INPUT': 5, 'IDENTICAL': 6, 'OUTPUT': 7, 'PROJECT': 8, 'ENGINE_OUTPUT_REJECTED': 9,
                          'PROVIDER': 10, 'NETWORK': 11, 'USAGE': 64, 'TIMEOUT': 124, 'CANCELLED': 130}
    assert len(set(EXIT_CODES.values())) == len(EXIT_CODES)


def test_backend_capabilities_extension_keeps_old_data_valid():
    old = {'schema_version': 1, 'id': 'c', 'name': 'ghidriff', 'version': '0.6', 'decompiler': True,
           'instruction_mapping': False, 'progress_counts': False, 'limitations': []}
    caps = BackendCapabilities.model_validate(old)
    assert caps.engines == [] and caps.options == []
    assert BackendCapabilities(version='x', engines=['SimpleDiff'], options=['--bsim']).engines == ['SimpleDiff']


@pytest.mark.parametrize('name,model', [('PatchTraceConfig', PatchTraceConfig), ('CliRunReport', CliRunReport),
                                        ('BackendCapabilities', BackendCapabilities)])
def test_generated_schemas_current(name, model):
    schema = json.loads((ROOT / 'docs' / 'schemas' / f'{name}.json').read_text(encoding='utf-8'))
    generated = model.model_json_schema()
    schema.pop('$id'), schema.pop('$schema')
    assert schema == json.loads(json.dumps(generated))
    examples = json.loads((ROOT / 'docs' / 'schemas' / 'examples.json').read_text(encoding='utf-8'))
    model.model_validate(examples[name]['valid'])
    with pytest.raises(ValidationError):
        model.model_validate(examples[name]['invalid'])
