"""Agent skills vendored under skills/: every imported file matches the pinned upstream manifest.

The manifest (skills/PATCHTRACE-SKILLS-MANIFEST.json) is the handoff package's manifest, copied verbatim. Components
under MIT or Apache-2.0 are imported; CC-BY-SA-4.0 components and the optional optimizer protocols are deliberately
absent until the repository owner decides their licence and activation (see docs/specs/phase2/PROVENANCE.md).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / 'skills'
MANIFEST = json.loads((SKILLS / 'PATCHTRACE-SKILLS-MANIFEST.json').read_text(encoding='utf-8'))

IMPORTED = {
    'superpowers', 'caveman', 'binary-analysis-patterns', 'python-design-patterns', 'python-error-handling',
    'python-resource-management', 'python-testing-patterns', 'python-packaging', 'github-actions-templates',
}
DEFERRED_LICENCE = {'differential-review', 'property-based-testing'}  # CC-BY-SA-4.0: owner licence decision pending
DEFERRED_PROTOCOLS = {'antigravity-protocol', 'antigravity-protocol-v2', 'ultimate-protocol-simulator'}  # opt-in only


def _components():
    return {c['name']: c for c in MANIFEST['components']}


# The repository already holds the Superpowers licence under _third_party_licenses (earlier import); this relocation
# is the only difference from the manifest layout and is checked by hash like every other file.
RELOCATED = {'superpowers/LICENSE': '_third_party_licenses/obra-superpowers/LICENSE'}


def _repo_path(manifest_path: str) -> Path:
    # Superpowers is vendored flat under skills/ (its manifest paths carry a 'superpowers/' prefix).
    if manifest_path in RELOCATED:
        return SKILLS / RELOCATED[manifest_path]
    prefix = 'superpowers/'
    if manifest_path.startswith(prefix):
        return SKILLS / manifest_path[len(prefix):]
    return SKILLS / manifest_path


def test_manifest_schema_and_component_set():
    assert MANIFEST['schema_version'] == 1
    assert set(_components()) == IMPORTED | DEFERRED_LICENCE | DEFERRED_PROTOCOLS


@pytest.mark.parametrize('name', sorted(IMPORTED))
def test_imported_component_files_match_manifest_hashes(name):
    component = _components()[name]
    assert component['license'] in {'MIT', 'Apache-2.0'}, 'only permissive components are imported'
    assert component['files'], name
    for entry in component['files']:
        path = _repo_path(entry['path'])
        assert path.is_file(), entry['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256'], entry['path']


@pytest.mark.parametrize('name', sorted(DEFERRED_LICENCE | DEFERRED_PROTOCOLS))
def test_deferred_components_are_not_vendored(name):
    component = _components()[name]
    for entry in component['files']:
        assert not _repo_path(entry['path']).exists(), entry['path']
    assert not (SKILLS / name).exists()
