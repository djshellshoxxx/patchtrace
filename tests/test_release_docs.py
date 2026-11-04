"""User-facing download and install docs match the current build (SPEC-52 sections 1 and 10; RB-07 notices).

The facts come from the build files themselves: `installer/PatchTrace.nsi`, `tools/package_windows_installer.py`,
`tools/windows_version_info.py` and the asset and apt-get lists in `.github/workflows/qa-windows.yml`, read as plain
text (no YAML library, like tests/test_release_gate.py). Hermetic: repository files only; nothing here proves that a
release was published or that a Windows host behaves as described.
"""
from __future__ import annotations

import re
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
README = ROOT / 'README.md'
INSTALL = DOCS / 'install.md'
LINUX = DOCS / 'linux.md'
WINDOWS = DOCS / 'windows.md'
FIRST_LAUNCH = DOCS / 'help' / '02-windows-first-launch.md'
NSIS_SCRIPT = ROOT / 'installer' / 'PatchTrace.nsi'
INNO_SCRIPT = ROOT / 'installer' / 'PatchTrace.iss'
CALLS_PANEL = ROOT / 'src' / 'patchtrace' / 'callgraph' / 'panel.py'
WORKFLOW = (ROOT / '.github' / 'workflows' / 'qa-windows.yml').read_text(encoding='utf-8')
PACKAGE_VERSION = '0.1.0'
SIGNING_POLICY = 'windows-release-signing-policy.md'


def _text(path: Path) -> str:
    return path.read_text(encoding='utf-8')


def _tool(name: str) -> dict:
    return runpy.run_path(str(ROOT / 'tools' / f'{name}.py'))


def _jobs(text: str) -> dict[str, str]:
    body = text.split('\njobs:\n', 1)[1]
    parts = re.split(r'^  ([A-Za-z0-9_-]+):[ ]*$', body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


JOBS = _jobs(WORKFLOW)


def _steps(job: str) -> list[str]:
    return re.split(r'\n(?=      - )', JOBS[job])


def _key(step: str, key: str) -> str | None:
    match = re.search(rf'^\s+{key}: (\S+)$', step, re.M)
    return match.group(1) if match else None


def _uploaded(artifact: str) -> list[str]:
    for job in JOBS:
        for step in _steps(job):
            if 'actions/upload-artifact@' in step and _key(step, 'name') == artifact:
                return [Path(path).name for path in re.findall(r'^\s+(dist/\S+)$', step, re.M)]
    raise AssertionError(f'no upload-artifact step named {artifact}')


def _release_assets() -> list[str]:
    """Every file the release job attaches: `files: release/*` takes the downloaded artifacts plus what it makes."""
    steps = _steps('release')
    downloaded = [_key(step, 'name') for step in steps
                  if 'actions/download-artifact@' in step and _key(step, 'path') == 'release']
    names = [name for artifact in downloaded for name in _uploaded(artifact)]
    for step in steps:
        if re.search(r'^\s+cd release$', step, re.M):
            names += re.findall(r'^\s+cp \S+ (\S+)$', step, re.M)
            names += re.findall(r' > (\S+)$', step, re.M)
    return sorted(set(names))


def _smoke_packages() -> list[str]:
    step = next(step for step in _steps('linux-smoke') if 'apt-get install' in step)
    packages = step.split('apt-get install -y', 1)[1].split()
    return [package for package in packages if package != 'xvfb']


def _mentions(name: str, text: str) -> bool:
    """`name` as a whole file name: `x.zip` does not count as mentioned by `x.zip.sha256`."""
    return re.search(re.escape(name) + r'(?![\w-]|\.\w)', text) is not None


def _download_section() -> str:
    text = _text(README)
    start = text.index('\n## Download and first launch\n')
    end = text.index('\n## ', start + 1)
    return text[start:end]


ASSETS = _release_assets()
SMOKE_PACKAGES = _smoke_packages()


def test_the_workflow_parse_is_not_vacuous():
    assert re.search(r'^\s+files: release/\*$', JOBS['release'], re.M)
    assert {f'PatchTrace-{PACKAGE_VERSION}-windows-x64.zip', 'PatchTrace-Windows-x64-Setup.exe',
            'PatchTrace-Windows-x64-Portable.zip', f'PatchTrace-{PACKAGE_VERSION}-linux-x86_64.tar.gz'} <= set(ASSETS)
    assert all(f'{name}.sha256' in ASSETS for name in ASSETS if not name.endswith('.sha256')), ASSETS
    assert len(SMOKE_PACKAGES) >= 10 and 'libxcb-cursor0' in SMOKE_PACKAGES and 'xvfb' not in SMOKE_PACKAGES


def test_no_doc_names_inno_setup_while_the_installer_is_nsis():
    pages = [README, *sorted(DOCS.glob('*.md')), *sorted((DOCS / 'help').glob('*.md'))]
    hits = [f'{page.relative_to(ROOT).as_posix()}:{number}'
            for page in pages for number, line in enumerate(_text(page).splitlines(), 1)
            if re.search(r'Inno Setup|PatchTrace\.iss', line, re.I)]
    assert INNO_SCRIPT.exists() or not hits, hits


def test_windows_page_names_the_nsis_script_and_its_pinned_version():
    text = _text(WINDOWS)
    assert NSIS_SCRIPT.is_file()
    assert 'installer/PatchTrace.nsi' in text
    assert f'NSIS {_tool("package_windows_installer")["NSIS_VERSION"]}' in text


@pytest.mark.parametrize('page', [README, INSTALL, FIRST_LAUNCH], ids=['readme', 'install', 'help02'])
def test_no_page_says_there_is_no_installer_while_setup_is_built(page):
    hits = re.findall(r'[^.\n]*\b(?:no installer|without an installer)\b[^.\n]*', _text(page), re.I)
    assert not NSIS_SCRIPT.is_file() or not hits, hits


@pytest.mark.parametrize('asset', ASSETS)
def test_install_page_names_every_release_asset(asset):
    text = _text(INSTALL)
    assert _mentions(asset, text) or _mentions(asset.replace(PACKAGE_VERSION, '<version>'), text), asset


def test_readme_download_section_links_the_releases_page_and_states_the_signing_policy():
    section = _download_section()
    assert re.search(r'\]\(https://github\.com/[\w.-]+/[\w.-]+/releases\)', section), 'no link to the Releases page'
    for phrase in ('unsigned', 'SmartScreen', SIGNING_POLICY, 'PatchTrace-Windows-x64-Setup.exe',
                   'PatchTrace-Windows-x64-Portable.zip'):
        assert phrase in section, phrase
    for name in ('PatchTrace-Windows-x64-Setup.exe', f'PatchTrace-{PACKAGE_VERSION}-windows-x64.zip'):
        assert re.search(rf"Get-FileHash '?\.\\{re.escape(name)}'? -Algorithm SHA256", section), name


def test_readme_never_hard_codes_a_release_or_the_latest_link():
    text = _text(README)
    assert '/releases/latest' not in text   # GitHub's latest skips prereleases: 404 while only prereleases exist
    assert 'releases/tag/v0.1.0-beta.' not in text


def test_readme_makes_no_frozen_test_count_claim():
    hits = re.findall(r'\b\d+ (?:Windows|Linux) tests\b', _text(README))
    assert not hits, hits


def test_readme_does_not_deny_the_built_calls_panel():
    hits = re.findall(r'Call-graph visualization[^.]*not implemented', _text(README), re.I)
    assert not CALLS_PANEL.is_file() or not hits, hits


@pytest.mark.parametrize('page', [LINUX, INSTALL], ids=['linux', 'install'])
def test_linux_prerequisites_list_every_package_the_smoke_job_installs(page):
    text = _text(page)
    missing = [p for p in SMOKE_PACKAGES if not re.search(rf'(?<![\w-]){re.escape(p)}(?![\w-])', text)]
    assert not missing, missing


def test_windows_page_states_the_signing_policy_and_the_version_resource():
    text = _text(WINDOWS)
    fields = _tool('windows_version_info')['VersionFields']('0.1.0-beta.1', (0, 1, 0, 1), 'f' * 40, 'Copyright (c) 1 X')
    comments = fields.strings()['Comments'].replace('f' * 40, '<sha>')
    assert SIGNING_POLICY in text and 'unsigned' in text.lower()
    assert 'ProductVersion' in text and comments in text, comments
