"""TB-16: pathologically nested JSON from outside the process fails typed, never with RecursionError.

`RecursionError` is a `RuntimeError`, so an `except ValueError` around `json.loads` does not stop it. Each case
reaches its parse site through the public entry point with real files in `tmp_path`; nothing is mocked. The
hostile documents are a few synthetic bytes built here (fixture evidence, not live evidence).
"""
from __future__ import annotations

import base64
import json

import pytest
from search_synergy_builders import attention, extra_specs, make_project

from patchtrace import raw_cleanup
from patchtrace.backend_bundle import BundleError, BundleRef, find_bundled_runtime, is_full_verified
from patchtrace.calibration.artifact import ArtifactError, load_artifact, parse_artifact, strict_json
from patchtrace.diaphora import provenance
from patchtrace.diaphora.contracts import DiaphoraError
from patchtrace.models import AnalystAnnotation
from patchtrace.reports import ExportError, export_project
from patchtrace.sample import create_sample
from patchtrace.search.contracts import SearchRequest
from patchtrace.search.errors import SearchError
from patchtrace.search.query import parse_query
from patchtrace.search.service import SearchService

DEEP = {'array': '[' * 60000, 'object': '{"a":' * 60000}
deep = pytest.mark.parametrize('text', list(DEEP.values()), ids=list(DEEP))


def closed(depth: int, shape: str) -> str:
    """Well-formed JSON that the C parser accepts but that is deeper than the Python frame limit."""
    return '[' * depth + '1' + ']' * depth if shape == 'array' else '{"a":' * depth + '1' + '}' * depth


# ---- reports: a match-override annotation in a shared project carries JSON text ----------------

@deep
def test_export_blanks_a_deep_match_override(tmp_path, text):
    project = create_sample(tmp_path / 'p').project
    project.annotations.append(AnalystAnnotation(target_id=project.matches[0].id, kind='match-override', text=text))
    out = tmp_path / 'report.json'
    export_project(project, 'json', out, include_code=False)
    exported = [a for a in json.loads(out.read_text(encoding='utf-8'))['annotations'] if a['kind'] == 'match-override']
    assert [a['text'] for a in exported] == ['']  # the same unreadable value as for malformed JSON


def test_export_rejects_a_deep_ranking_input(tmp_path):
    project = create_sample(tmp_path / 'p').project
    ranking: dict = {}
    for _ in range(60000):
        ranking = {'a': ranking}
    with pytest.raises(ExportError, match='PT-EXPORT: ranking failed validation'):
        export_project(project, 'json', tmp_path / 'report.json', enrichment={'ranking': ranking, 'stale': False})
    assert not (tmp_path / 'report.json').exists()


# ---- search: the page cursor is caller text ---------------------------------------------------

@deep
def test_search_cursor(tmp_path, text):
    service = SearchService(make_project(tmp_path / 'project'), tmp_path / 'cache', attention=attention,
                            comparable=lambda engine: True, extra_specs=extra_specs)
    cursor = base64.urlsafe_b64encode(text.encode('ascii')).decode('ascii').rstrip('=')
    # model_copy does not re-validate, so the 512-character contract bound cannot be what protects the parser.
    request = SearchRequest(plan=parse_query('container', mode='auto'), limit=1).model_copy(update={'cursor': cursor})
    with pytest.raises(SearchError) as caught:
        service.search(request)
    assert caught.value.code == 'PT-SEARCH-INPUT'


# ---- calibration: artifact bytes --------------------------------------------------------------

@deep
def test_calibration_strict_json(text):
    with pytest.raises(ValueError, match='nesting'):
        strict_json(text.encode('ascii'))


@deep
def test_calibration_artifact(text):
    with pytest.raises(ArtifactError, match='not strict JSON'):
        parse_artifact(text.encode('ascii'))
    assert load_artifact(text.encode('ascii')).artifact is None


@pytest.mark.parametrize('shape', ['array', 'object'])
def test_calibration_artifact_parsed_but_deep(shape):
    data = closed(3000, shape).encode('ascii')
    assert strict_json(data) is not None  # well formed for the parser: the walk after it must fail typed too
    with pytest.raises(ArtifactError):
        parse_artifact(data)
    assert load_artifact(data).artifact is None


# ---- diaphora: sidecar manifest next to an imported result ------------------------------------

# 13,000 object levels are 65,000 bytes: the deepest object document that still passes the 64 KiB size check.
@pytest.mark.parametrize('text', [*DEEP.values(), '{"a":' * 13000], ids=[*DEEP, 'object-under-limit'])
def test_diaphora_manifest(tmp_path, text):
    path = tmp_path / 'manifest.json'
    path.write_text(text, encoding='utf-8', newline='\n')
    with pytest.raises(DiaphoraError) as caught:
        provenance.load_manifest(path)
    assert caught.value.code == 'PT-DIAPHORA-PROVENANCE'


# ---- raw cleanup: the restore journal inside the project folder -------------------------------

@deep
def test_raw_duplicate_journal(tmp_path, text):
    journal = tmp_path / raw_cleanup.JOURNAL
    journal.parent.mkdir(parents=True)
    journal.write_text(text + '\n', encoding='ascii', newline='\n')
    with pytest.raises(ValueError, match=r'^PT-STORAGE: raw duplicate journal line 1 is malformed'):
        raw_cleanup.restore_raw_duplicates(tmp_path)


# ---- backend bundle: advisory marker in the work directory, manifest next to the executable ----

def bundle_ref(root, digest: str = 'a' * 64) -> BundleRef:
    payload = root / 'payload'
    return BundleRef(root=root, manifest_path=root / 'manifest.json', runtime_id='r', python=payload / 'python',
                     ghidra=payload / 'ghidra', java_home=payload / 'jdk', platform='linux', manifest_sha256=digest)


@deep
def test_bundle_marker(tmp_path, text):
    ref = bundle_ref(tmp_path / 'backend')
    work = tmp_path / 'work'
    work.mkdir()
    (work / f'bundle-verified-{ref.manifest_sha256}.json').write_text(text, encoding='utf-8', newline='\n')
    assert is_full_verified(ref, work) is False


@deep
def test_bundle_manifest(tmp_path, text):
    backend = tmp_path / 'backend'
    backend.mkdir()
    (backend / 'manifest.json').write_text(text, encoding='utf-8', newline='\n')
    with pytest.raises(BundleError) as caught:
        find_bundled_runtime(tmp_path, host='linux')
    assert caught.value.code == 'PT-BUNDLE-MANIFEST'
