"""Parser-recognized DTD refusal beyond the decoded-text screen; bounded authored data."""
from __future__ import annotations

import codecs
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pe_rsrc_builder import LANG_EN_US, RT_MANIFEST, open_pe, rsrc_pe, tree

from patchtrace.pe_overview import manifest
from patchtrace.pe_overview.metadata import inspect_metadata
from patchtrace.pe_overview.resources import ResourceLeaf

NORMAL = ('<assembly xmlns="urn:schemas-microsoft-com:asm.v1">'
          '<assemblyIdentity name="Authored.Normal"/></assembly>')
ENTITY = ('<!DOCTYPE assembly [<!ENTITY proof "AUTHORED_ENTITY_MARKER">]>'
          + NORMAL.replace('Authored.Normal', '&proof;'))
EMPTY_DTD = '<!DOCTYPE assembly>' + NORMAL
SRC = str(Path(manifest.__file__).resolve().parents[2])


def observe(raw):
    leaf = ResourceLeaf(RT_MANIFEST, 'RT_MANIFEST', 1, LANG_EN_US, 0x2000, len(raw), 0, 0x400)
    return manifest.observe_manifest(leaf, raw)


@pytest.mark.parametrize('prefix', [' ', '\n', '\t'])
@pytest.mark.parametrize('document', [ENTITY, EMPTY_DTD], ids=['internal-entity', 'doctype-only'])
def test_leading_utf16be_doctype_is_refused_by_the_parser(prefix, document):
    raw = (prefix + document).encode('utf-16-be')
    result = observe(raw)
    assert result.identity is None
    assert result.warnings == ('manifest_dtd_rejected',)
    assert result.sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize('encoding,bom,prefix', [
    ('utf-8', b'', ''), ('utf-8', b'', ' \n\t'),
    ('utf-8', codecs.BOM_UTF8, ''), ('utf-8', codecs.BOM_UTF8, ' \n\t'),
    ('utf-16-le', b'', ''), ('utf-16-be', b'', ''),
    ('utf-16-le', codecs.BOM_UTF16_LE, ''), ('utf-16-le', codecs.BOM_UTF16_LE, ' \n\t'),
    ('utf-16-be', codecs.BOM_UTF16_BE, ''), ('utf-16-be', codecs.BOM_UTF16_BE, ' \n\t'),
    ('utf-16-be', b'', ' \n\t'),
])
def test_normal_manifest_encodings_and_accepted_whitespace_keep_their_facts(encoding, bom, prefix):
    raw = bom + (prefix + NORMAL).encode(encoding)
    result = observe(raw)
    assert result.warnings == ()
    assert result.identity.name == 'Authored.Normal'
    assert result.sha256 == hashlib.sha256(raw).hexdigest()


def test_the_production_metadata_reader_refuses_a_hidden_doctype(tmp_path):
    raw = (' ' + ENTITY).encode('utf-16-be')
    data, _ = rsrc_pe(tree({RT_MANIFEST: {1: {LANG_EN_US: raw}}}))
    with open_pe(tmp_path, data) as pe:
        result = inspect_metadata(pe.reader, pe.overview)
    assert result.status == 'partial'
    assert len(result.manifests) == 1
    assert result.manifests[0].identity is None
    assert result.manifests[0].warnings == ('manifest_dtd_rejected',)
    assert result.manifests[0].sha256 == hashlib.sha256(raw).hexdigest()


def test_python_elementtree_fallback_also_refuses_internal_only_dtds():
    child = '''
import codecs, json, os, pathlib, sys
sys.modules['_elementtree'] = None
from patchtrace.pe_overview import manifest
from patchtrace.pe_overview.resources import ResourceLeaf
assert str(pathlib.Path(manifest.__file__).resolve().parents[2]) == os.environ['PYTHONPATH']
assert hasattr(manifest.ET.XMLParser(), 'parser')
normal = '<assembly xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Authored.Normal"/></assembly>'
entity = '<!DOCTYPE assembly [<!ENTITY proof "AUTHORED_ENTITY_MARKER">]>' + normal.replace('Authored.Normal', '&proof;')
values = [(' ' + entity).encode('utf-16-be'), ('\\n<!DOCTYPE assembly>' + normal).encode('utf-16-be'),
          normal.encode(), codecs.BOM_UTF16_LE + (' ' + normal).encode('utf-16-le'),
          codecs.BOM_UTF16_BE + (' ' + normal).encode('utf-16-be')]
found = []
for raw in values:
    leaf = ResourceLeaf(24, 'RT_MANIFEST', 1, 1033, 0x2000, len(raw), 0, 0x400)
    result = manifest.observe_manifest(leaf, raw)
    found.append({'warnings': result.warnings, 'identity': result.identity.name if result.identity else None})
assert not [m for m in sys.modules if m.startswith(('PySide6', 'shiboken6', 'patchtrace.ui'))]
print(json.dumps(found))
'''
    environment = dict(os.environ, PYTHONPATH=SRC, QT_QPA_PLATFORM='offscreen')
    completed = subprocess.run([sys.executable, '-c', child], env=environment, capture_output=True,
                               text=True, timeout=15)
    assert completed.returncode == 0, completed.stderr
    rows = json.loads(completed.stdout)
    assert rows[:2] == [{'warnings': ['manifest_dtd_rejected'], 'identity': None}] * 2
    assert rows[2:] == [{'warnings': [], 'identity': 'Authored.Normal'}] * 3
