"""Windows smoke prerequisites; configuration controls do not certify native tools."""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def documents():
    corpus = yaml.safe_load((ROOT / '.github/workflows/corpus-tier-r.yml').read_text())
    live = yaml.safe_load((ROOT / '.github/workflows/live-rizin.yml').read_text())
    return corpus, live


def test_windows_rizin_uses_existing_native_windows_asset_and_digest():
    corpus, live = documents()
    native = next(row for row in live['jobs']['live-rizin']['strategy']['matrix']['include']
                  if row['os'] == 'windows-latest')
    environment = corpus['jobs']['windows-advisory']['env']
    assert environment['RIZIN_ASSET'] == native['asset']
    assert environment['RIZIN_SHA256'] == native['sha256']
    assert environment['RIZIN_ASSET'] != corpus['env']['RIZIN_ASSET']
    assert corpus['env']['RIZIN_VERSION'] == live['env']['RIZIN_VERSION']


def test_complete_llvm_archive_is_always_verified_before_extraction_and_path_export():
    corpus, _ = documents()
    job = corpus['jobs']['windows-advisory']
    environment = job['env']
    assert environment['LLVM_WINDOWS_URL'].startswith('https://github.com/llvm/llvm-project/releases/download/')
    assert environment['LLVM_WINDOWS_URL'].endswith('x86_64-pc-windows-msvc.tar.xz')
    step = next(row for row in job['steps'] if row.get('name') == 'Install pinned complete LLVM tools')
    assert 'if' not in step
    script = step['run']
    assert script.index('Get-FileHash') < script.index('tar -xf') < script.index('$env:GITHUB_PATH')
    assert 'LLVM_WINDOWS_SHA256' in script and 'digest mismatch' in script
    assert 'ReparsePoint' in script and 'IO.FileInfo' in script
    assert script.index('runtime directory already exists') < script.index('tar -xf')
    assert script.index('llvm-dwarfdump.exe') < script.index('$env:GITHUB_PATH')
    assert '$LASTEXITCODE -ne 0' in script
    cache = next(row for row in job['steps'] if row.get('id') == 'llvm-windows-cache')
    assert cache['with']['path'].endswith('.tar.xz')
    assert '${{ env.LLVM_WINDOWS_SHA256 }}' in cache['with']['key']


def test_rizin_is_verified_before_extraction_and_exports_a_known_executable():
    corpus, _ = documents()
    job = corpus['jobs']['windows-advisory']
    step = next(row for row in job['steps'] if row.get('name') == 'Install pinned Windows rizin')
    script = step['run']
    assert script.index('Get-FileHash') < script.index('Expand-Archive') < script.index('RZ_DIFF=')
    assert 'RIZIN_SHA256' in script and 'digest mismatch' in script
    assert 'rz-diff.exe' in script and '$env:GITHUB_PATH' in script


def test_selecting_archive_clang_keeps_its_adjacent_builtin_headers():
    corpus, _ = documents()
    step = next(row for row in corpus['jobs']['windows-advisory']['steps']
                if row.get('name') == 'Install pinned complete LLVM tools')
    script = step['run']
    extract = next(line for line in script.splitlines() if line.strip().startswith('tar -xf'))
    assert ')/lib/clang' in extract
    assert script.index('-print-resource-dir') < script.index('$env:GITHUB_PATH')
    assert script.index('include/stddef.h') < script.index('$env:GITHUB_PATH')


def test_setup_does_not_remove_smoke_cases_or_change_advisory_classification():
    corpus, _ = documents()
    job = corpus['jobs']['windows-advisory']
    assert job['continue-on-error'] is True and job['timeout-minutes'] == 45
    step = next(row for row in job['steps'] if row.get('name') == 'Plan and run the smoke subset as one shard')
    assert '--subset smoke' in step['run'] and '--shards 1' in step['run']
    assert '--plan plan.json --shard 0' in step['run'] and '--timeout 1200' in step['run']
    assert '--cases' not in step['run'] and '--engines' not in step['run']
    assert not step.get('continue-on-error')
    uploads = [row for row in job['steps'] if 'upload-artifact@' in row.get('uses', '')]
    assert len(uploads) == 1 and uploads[0]['if'] == 'always()'
    assert 'shard-out/shard-*.json' in uploads[0]['with']['path']
    assert 'windows-toolchain.json' in uploads[0]['with']['path']
