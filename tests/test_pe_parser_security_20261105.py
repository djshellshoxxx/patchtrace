"""Authored PE resource bytes; a closed XML prefix cannot prove an incompletely backed manifest."""
from __future__ import annotations

import codecs
import hashlib

import pytest
from pe_rsrc_builder import RT_MANIFEST, Data, open_pe, rsrc_pe, tree

from patchtrace.pe_overview import manifest
from patchtrace.pe_overview.metadata import inspect_metadata
from patchtrace.pe_overview.resources import ResourceLeaf, parse_resources

XML = ('<assembly xmlns="urn:schemas-microsoft-com:asm.v1">'
       '<assemblyIdentity name="Authored.App" version="1.0.0.0"/>'
       '<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>'
       '<requestedExecutionLevel level="requireAdministrator" uiAccess="true"/>'
       '</requestedPrivileges></security></trustInfo>'
       '</assembly>')


def assert_unavailable(observation):
    assert observation.sha256 is None
    assert observation.warnings == ('manifest_xml_invalid',)
    assert observation.identity is None
    assert observation.execution_level is None and observation.ui_access is None
    assert observation.dependencies == () and observation.files == ()


@pytest.mark.parametrize('raw', [XML.encode(), codecs.BOM_UTF16_LE + XML.encode('utf-16-le')],
                         ids=['utf8', 'utf16'])
def test_closed_xml_in_incomplete_resource_never_becomes_unflagged_facts(raw):
    leaf = ResourceLeaf(RT_MANIFEST, 'RT_MANIFEST', 1, 0, 0x2000, len(raw) + 512, 0, 0x400)
    assert_unavailable(manifest.observe_manifest(leaf, raw, complete=False))


@pytest.mark.parametrize('unbacked', [False, True], ids=['fully-backed', 'unbacked-tail'])
def test_manifest_backing_controls_metadata_status_through_real_pe_parser(tmp_path, unbacked):
    raw = XML.encode()
    data, _info = rsrc_pe(tree({RT_MANIFEST: {1: {0: Data(raw, size=len(raw) + (512 if unbacked else 0))}}}))
    with open_pe(tmp_path, data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        (observed,) = manifest.parse_manifests(pe.ctx, pe.smap, inventory)
        metadata = inspect_metadata(pe.reader, pe.overview)
        if unbacked:
            assert_unavailable(observed)
            assert metadata.status == 'partial'
            assert 'manifest_xml_invalid' in {warning.code for warning in metadata.warnings}
            assert_unavailable(metadata.manifests[0])
        else:
            assert metadata.status == 'ok' and metadata.warnings == ()
            assert observed.identity.name == 'Authored.App'
            assert observed.execution_level == 'requireAdministrator' and observed.ui_access is True
            assert observed.sha256 == hashlib.sha256(raw).hexdigest()
    assert (tmp_path / 'sample.bin').read_bytes() == data


def test_incomplete_manifest_is_refused_before_xml_parser_runs(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('unbacked manifest reached the XML parser')

    monkeypatch.setattr(manifest.ET, 'fromstring', forbidden)
    raw = XML.encode()
    leaf = ResourceLeaf(RT_MANIFEST, 'RT_MANIFEST', 1, 0, 0x2000, len(raw) + 1, 0, 0x400)
    assert_unavailable(manifest.observe_manifest(leaf, raw, complete=False))
