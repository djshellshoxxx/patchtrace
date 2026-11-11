"""SPEC-31 S1 packaging: the extractor script as a frozen data file, the BinDiff v8 notice, the build-script gates.

Static checks only (the Windows frozen run is the gate; the Linux frozen run is recorded in docs/qa.md)."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from test_unified_ir_ingest import recorded

from patchtrace.unified import extract
from patchtrace.unified.ir import mdindex

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools'
NOTICES = ROOT / 'third_party' / 'notices'
BINDIFF = NOTICES / 'bindiff-v8-aecc14d'
SCRIPT = ROOT / 'src' / 'patchtrace' / 'unified' / 'extract' / 'ghidra_script.py'


def load_tool(name: str):
    spec = importlib.util.spec_from_file_location(f'pt_tool_{name}', TOOLS / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def test_packaged_resource_is_the_source_file():
    assert extract.script_bytes() == SCRIPT.read_bytes()
    assert extract.script_sha256() == hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
    assert extract.SCRIPT_NAME == SCRIPT.name


def test_hook_ships_exactly_the_script_as_data():
    namespace = {'__file__': str(TOOLS / 'pyinstaller_hooks' / 'hook-patchtrace.unified.extract.py')}
    exec(compile(Path(namespace['__file__']).read_text(encoding='utf-8'), namespace['__file__'], 'exec'), namespace)
    assert namespace['datas'] == [(str(SCRIPT), 'patchtrace/unified/extract')]
    assert 'hiddenimports' not in namespace                      # nothing is imported, the script is a data file


def test_hook_refuses_to_build_without_the_script(tmp_path):
    fake = tmp_path / 'tools' / 'pyinstaller_hooks' / 'hook-patchtrace.unified.extract.py'
    fake.parent.mkdir(parents=True)
    source = (TOOLS / 'pyinstaller_hooks' / 'hook-patchtrace.unified.extract.py').read_text(encoding='utf-8')
    namespace = {'__file__': str(fake)}
    with pytest.raises(SystemExit) as caught:
        exec(compile(source, str(fake), 'exec'), namespace)
    assert 'PT-BUILD' in str(caught.value)


@pytest.mark.parametrize('name', ['build_windows', 'build_linux'])
def test_build_scripts_require_the_bindiff_notice_and_verify_the_script(name):
    module = load_tool(name)
    text = (TOOLS / f'{name}.py').read_text(encoding='utf-8')
    required = getattr(module, 'REQUIRED_NOTICES', None) or (module.BINEXPORT_NOTICES + module.BINDIFF_NOTICES)
    assert {'bindiff-v8-aecc14d/LICENSE', 'bindiff-v8-aecc14d/PROVENANCE.txt'} <= set(required)
    assert all((NOTICES / item).is_file() for item in required if item.startswith('bindiff-'))
    assert module.EXTRACTOR_SCRIPT == 'patchtrace/unified/extract/ghidra_script.py'
    assert (ROOT / 'src' / module.EXTRACTOR_SCRIPT).is_file()
    assert 'Extractor script data file is missing or differs' in text            # the inventory gate exists


def test_bindiff_notice_is_the_unmodified_apache_license_with_matching_provenance():
    license_bytes = (BINDIFF / 'LICENSE').read_bytes()
    provenance = (BINDIFF / 'PROVENANCE.txt').read_text(encoding='utf-8')
    assert b'Apache License' in license_bytes and b'Version 2.0, January 2004' in license_bytes
    assert hashlib.sha256(license_bytes).hexdigest() in provenance and f'({len(license_bytes)} bytes)' in provenance
    assert 'aecc14dcc2e0f06a0f8957dc465a9073215b5920' in provenance and 'no NOTICE file' in provenance
    assert 'MODIFIED' in provenance and 'bindiff --md_index' in provenance


def test_mdindex_header_carries_the_attribution_and_the_same_commit():
    header = mdindex.__doc__
    assert 'Apache License, Version 2.0' in header and 'MODIFIED' in header and 'Google LLC' in header
    assert 'aecc14dcc2e0f06a0f8957dc465a9073215b5920' in header and 'bindiff-v8-aecc14d' in header
    assert 'aecc14dcc2e0f06a0f8957dc465a9073215b5920' in (BINDIFF / 'PROVENANCE.txt').read_text(encoding='utf-8')


def test_no_gpl_or_third_party_graph_code_is_vendored_under_unified():
    documents_licences = {'registry.py'}  # records the licence of each EXTERNAL engine process (data, never vendored code)
    for path in (ROOT / 'src' / 'patchtrace' / 'unified').rglob('*.py'):
        if path.name in documents_licences:
            continue
        text = path.read_text(encoding='utf-8')
        assert not re.search(r'GNU General Public|GPL-[23]|yFiles|#include\s*<', text), path


def test_gitattributes_pin_the_notice_bytes_and_the_recorded_fixtures():
    attributes = (ROOT / '.gitattributes').read_text(encoding='utf-8').splitlines()
    assert 'third_party/notices/bindiff-v8-aecc14d/LICENSE -text' in attributes
    assert 'tests/fixtures/unified/*.jsonl text eol=lf' in attributes
    assert 'src/patchtrace/unified/extract/ghidra_script.py text eol=lf' in attributes   # one script hash on every OS


def test_frozen_smoke_unified_checks_pass_on_a_faithful_layout_and_fail_otherwise(tmp_path):
    smoke = load_tool('frozen_smoke')
    package = tmp_path / 'PatchTrace'
    target = package / '_internal' / 'patchtrace' / 'unified' / 'extract' / 'ghidra_script.py'
    target.parent.mkdir(parents=True)
    notice = package / 'licenses' / 'upstream' / 'bindiff-v8-aecc14d' / 'LICENSE'
    notice.parent.mkdir(parents=True)
    launcher = [str(package / 'PatchTrace')]
    results = []

    def check(label, ok, detail=''):
        results.append((label, bool(ok)))

    smoke.unified_checks(launcher, frozen=False, check=check)
    assert results == []                                                       # source runs are not frozen
    target.write_bytes(SCRIPT.read_bytes())
    notice.write_bytes(b'x')
    smoke.unified_checks(launcher, frozen=True, check=check, source_root=tmp_path / 'no-source')  # U2 SKIP
    assert [ok for _, ok in results] == [True, True, True]
    results.clear()
    target.write_bytes(SCRIPT.read_bytes() + b'# tampered\n')
    notice.unlink()
    smoke.unified_checks(launcher, frozen=True, check=check, source_root=tmp_path / 'no-source')  # U2 SKIP
    assert [ok for _, ok in results] == [True, False, False]
    results.clear()
    target.unlink()
    smoke.unified_checks(launcher, frozen=True, check=check, source_root=tmp_path / 'no-source')  # U2 SKIP
    assert [(label.split()[1], ok) for label, ok in results] == [('extractor', False), ('BinDiff', False)]


def test_frozen_smoke_runs_the_unified_cli_checks_only_when_the_cli_exists(tmp_path):
    smoke = load_tool('frozen_smoke')
    package = tmp_path / 'PatchTrace'
    script = package / '_internal' / 'patchtrace' / 'unified' / 'extract' / 'ghidra_script.py'
    script.parent.mkdir(parents=True)
    script.write_bytes(SCRIPT.read_bytes())
    notice = package / 'licenses' / 'upstream' / 'bindiff-v8-aecc14d' / 'LICENSE'
    notice.parent.mkdir(parents=True)
    notice.write_bytes(b'x')
    results, lines, calls = [], [], []
    source = tmp_path / 'source'
    smoke.unified_checks([str(package / 'PatchTrace')], frozen=True, check=lambda label, ok, detail='': results.append(label),
                         emit=lines.append, source_root=source)
    assert len(results) == 3 and lines and lines[0].startswith('SKIP U2')        # no cli.py: skipped, not failed
    (source / 'src' / 'patchtrace' / 'unified').mkdir(parents=True)
    (source / 'src' / 'patchtrace' / 'unified' / 'cli.py').write_text('x', encoding='utf-8')

    class Done:
        returncode, stdout, stderr = 0, 'usage: patchtrace unified', ''

    def fake_run(launcher, *args, **kwargs):
        calls.append(args)
        return Done()

    smoke.run = fake_run
    results.clear()
    smoke.unified_checks([str(package / 'PatchTrace')], frozen=True, check=lambda label, ok, detail='': results.append(
        (label, bool(ok))), emit=lines.append, source_root=source)
    assert calls == [('unified', '--help'), ('unified', '_worker', '--self-check')]
    assert [label for label, _ in results][-2:] == ['U2 unified --help', 'U2 unified _worker --self-check']
    assert all(ok for _, ok in results)


# --- import rules (01 s3) for the S1 modules --------------------------------------------------------------------------

UNIFIED = ROOT / 'src' / 'patchtrace' / 'unified'
S1_ALLOWED = {
    'extract/__init__': set(), 'extract/retain': {'patchtrace.unified.limits'},
    'extract/decomp': {'patchtrace.unified.contracts', 'patchtrace.unified.limits'},   # S3b: the strict reader of decomp.jsonl
    'extract/runner': {'patchtrace', 'patchtrace.backend', 'patchtrace.jobs', 'patchtrace.unified',
                       'patchtrace.unified.contracts', 'patchtrace.unified.extract', 'patchtrace.unified.extract.decomp',
                       'patchtrace.unified.limits', 'pydantic'},
    'ir/__init__': set(), 'ir/cfg': set(), 'ir/features': set(), 'ir/mdindex': set(), 'ir/operands': set(),
    'ir/ingest': {'patchtrace.unified', 'patchtrace.unified.contracts', 'patchtrace.unified.ir',
                  'patchtrace.unified.ir.cfg', 'patchtrace.unified.ir.features', 'patchtrace.unified.ir.ins',
                  'patchtrace.unified.ir.mdindex', 'patchtrace.unified.ir.operands', 'patchtrace.unified.ir.records',
                  'patchtrace.unified.limits'},
    'ir/ins': {'patchtrace.unified.ir.schema'},
    'ir/ladder_port': {'patchtrace.unified.ir', 'patchtrace.unified.ir.features', 'patchtrace.unified.ir.reader',
                       'patchtrace.unified.ir.schema', 'patchtrace.unified.ladder.ports',
                       'patchtrace.unified.limits'},                        # S3/S5: the IrReader as the ladder's IrSide
    'ir/pe_tables': {'patchtrace.artifact_bytes', 'patchtrace.pe_overview', 'patchtrace.unified.limits'},
    'ir/place': {'patchtrace.ingestion', 'patchtrace.unified.contracts', 'patchtrace.unified.ir',
                 'patchtrace.unified.ir.reader', 'patchtrace.unified.limits'},
    'ir/reader': {'patchtrace.unified.contracts', 'patchtrace.unified.ir', 'patchtrace.unified.ir.features',
                  'patchtrace.unified.ir.ins', 'patchtrace.unified.limits', 'pydantic'},
    'ir/records': {'patchtrace.unified.contracts', 'patchtrace.unified.limits'},
    'ir/schema': {'patchtrace.unified.limits'},
}
FORBIDDEN = {'PySide6', 'urllib', 'http', 'socket', 'ssl', 'subprocess', 'ctypes', 'ghidriff', 'pyghidra', 'jpype',
             'multiprocessing', 'ftplib', 'smtplib', 'requests'}


def imports_of(path: Path) -> set[str]:
    package = 'patchtrace.unified.' + path.parent.name
    imported = set()
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ''
            if node.level:
                parts = package.split('.')
                module = '.'.join(parts[:len(parts) - (node.level - 1)] + ([module] if module else []))
            imported.add(module)
    return imported


def test_every_s1_module_is_covered_by_the_import_rules():
    on_disk = {f'{p.parent.name}/{p.stem}' for d in ('ir', 'extract') for p in (UNIFIED / d).glob('*.py')}
    assert on_disk - {'extract/ghidra_script'} == set(S1_ALLOWED)


@pytest.mark.parametrize('module', sorted(S1_ALLOWED))
def test_s1_modules_respect_the_import_dag(module):
    imported = imports_of(UNIFIED / f'{module}.py')
    external = {m for m in imported if m.split('.')[0] not in sys.stdlib_module_names}
    assert external <= S1_ALLOWED[module], external - S1_ALLOWED[module]
    assert not {m.split('.')[0] for m in imported} & FORBIDDEN
    assert not any(m.startswith('patchtrace.ui') for m in imported)


def test_ir_modules_never_import_extract_backend_or_jobs():
    for path in (UNIFIED / 'ir').glob('*.py'):
        imported = imports_of(path)
        assert not any(m.startswith(('patchtrace.unified.extract', 'patchtrace.backend', 'patchtrace.jobs'))
                       for m in imported), path


def test_ir_and_retention_import_without_qt_network_or_process_modules():
    code = ('import sys\nclass Block:\n    def find_spec(self, name, path=None, target=None):\n'
            '        if name.split(".")[0] == "PySide6": raise ImportError("blocked")\n'
            'sys.meta_path.insert(0, Block())\n'
            'import patchtrace.unified.ir.ingest, patchtrace.unified.ir.reader, patchtrace.unified.ir.place\n'
            'import patchtrace.unified.ir.pe_tables, patchtrace.unified.extract.retain\n'
            'bad = [m for m in ("PySide6", "subprocess", "ssl", "urllib.request", "http.client", "ctypes")\n'
            '       if m in sys.modules]\nprint(bad)\nraise SystemExit(1 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stdout + result.stderr


# --- recorded fixtures ------------------------------------------------------------------------------------------------

FIXTURES = ROOT / 'tests' / 'fixtures' / 'unified'
PROVENANCE = json.loads((FIXTURES / 'PROVENANCE.json').read_text(encoding='utf-8'))


def test_every_recorded_fixture_has_a_provenance_entry_and_the_reverse():
    on_disk = {p.name.removesuffix('.ir.jsonl') for p in FIXTURES.glob('*.ir.jsonl')}
    assert on_disk == set(PROVENANCE) == {p.name.removesuffix('.pe.json') for p in FIXTURES.glob('*.pe.json')}


@pytest.mark.parametrize('name', sorted(PROVENANCE))
def test_recorded_fixture_matches_its_provenance(name, tmp_path):
    entry = PROVENANCE[name]
    header = json.loads((FIXTURES / f'{name}.ir.jsonl').read_text(encoding='utf-8').splitlines()[0])
    pe = json.loads((FIXTURES / f'{name}.pe.json').read_text(encoding='utf-8'))
    assert header['artifact_sha256'] == header['program_sha256'] == pe['sha256'] == entry['artifact_sha256']
    assert header['producer']['script_sha256'] == entry['script_sha256'] and header['producer']['mode'] == 'analyze'
    assert {k: header['producer'][k] for k in ('ghidra', 'pyghidra', 'java', 'python')} == {
        k: entry['probe'][k] for k in ('ghidra', 'pyghidra', 'java', 'python')}
    assert recorded(tmp_path, name).manifest.content_digest == entry['content_digest']
    assert entry['built_with'] != 'unspecified' and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', entry['recorded_utc'])


def test_golden_digests_agree_with_the_provenance_record():
    golden = json.loads((FIXTURES / 'golden.json').read_text(encoding='utf-8'))
    assert golden['probe_old']['content_digest'] == PROVENANCE['probe_old']['content_digest']
