"""The Pages lane installs a complete, hashed site-only closure and keeps app fixtures out."""
from __future__ import annotations

import re
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'tools/site/requirements-ci.lock'
WORKFLOW = ROOT / '.github/workflows/pages.yml'
REQUIREMENT = re.compile(r'([a-z][a-z0-9-]*)==([0-9]+(?:\.[0-9]+)*) --hash=sha256:([0-9a-f]{64})')


def _requirements():
    result = {}
    for line in LOCK.read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = REQUIREMENT.fullmatch(line)
        assert match, f'Every CI requirement needs an exact version and SHA-256: {line!r}'
        name, version, digest = match.groups()
        assert name not in result, f'Duplicate CI requirement: {name}'
        result[name] = (version, digest)
    return result


def _command(prefix):
    # One-line run commands are the Pages contract; no YAML or app dependency is needed here.
    matches = re.findall(r'^        run: "?(' + re.escape(prefix) + r'[^"\n]*)"?$',
                         WORKFLOW.read_text(encoding='utf-8'), re.M)
    assert len(matches) == 1, matches
    return shlex.split(matches[0])


def test_ci_lock_contains_only_the_complete_linux_site_test_and_build_closure():
    requirements = _requirements()
    assert set(requirements) == {'segno', 'pillow', 'pytest', 'iniconfig', 'packaging', 'pluggy', 'pygments'}
    assert requirements['pytest'][0] == '9.2.0'


def test_portable_build_declarations_keep_the_same_versions_in_the_ci_lock():
    requirements = _requirements()
    portable = {}
    for line in (ROOT / 'tools/site/requirements.txt').read_text(encoding='utf-8').splitlines():
        if line and not line.startswith('#'):
            name, version = line.split('==')
            portable[name] = version
    assert set(portable) == {'segno', 'pillow'}
    assert all(requirements[name][0] == version for name, version in portable.items())


def test_pages_install_requires_hashes_for_the_lock_and_resolves_dependencies():
    args = _command('python -m pip install ')
    assert args[:4] == ['python', '-m', 'pip', 'install']
    assert set(args[4:]) == {'--require-hashes', '--only-binary=:all:', '-r', 'tools/site/requirements-ci.lock'}
    assert len(args[4:]) == 4
    assert args[args.index('-r') + 1] == 'tools/site/requirements-ci.lock'


def test_pages_site_tests_keep_the_full_selection_and_isolate_application_fixtures():
    args = _command('python -m pytest ')
    assert args[:3] == ['python', '-m', 'pytest']
    assert set(args[3:]) == {'--noconftest', '--disable-plugin-autoload', '-q', 'tests/test_site_*.py'}
    assert len(args[3:]) == 4
