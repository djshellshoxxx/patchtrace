"""Verified-bytes identity facts (SPEC-28 section G): VS_FIXEDFILEINFO and CodeView from SYNTHETIC PE images
built by tests/pe_builder.py (never executed). Hostile resource trees must degrade to a note, never raise."""
from __future__ import annotations

import struct
import threading
from pathlib import Path

import pytest
from pe_builder import RDATA, PeSpec, SectionSpec, build_pe

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import identity as idt
from patchtrace.service import ProjectService

RSRC_RVA = 0x2000  # second section: .text at 0x1000, .rsrc at 0x2000
GUID = bytes(range(16))


def version_blob(file_ms: int, file_ls: int, prod_ms: int, prod_ls: int, *, signature: int = idt.VS_SIGNATURE,
                 key: str = 'VS_VERSION_INFO\0', value_length: int = 52) -> bytes:
    fixed = struct.pack('<13I', signature, 0x10000, file_ms, file_ls, prod_ms, prod_ls, 0x3F, 0, 0x40004, 2, 0, 0, 0)
    head = struct.pack('<HHH', 0, value_length, 0) + key.encode('utf-16-le')
    head += b'\0' * (-len(head) % 4)
    body = head + fixed
    return struct.pack('<H', len(body)) + body[2:]


def directory(entries: list[tuple[int, int]]) -> bytes:
    return struct.pack('<IIHHHH', 0, 0, 0, 0, 0, len(entries)) + b''.join(struct.pack('<II', i, t) for i, t in entries)


def resource_tree(blob: bytes, *, type_id: int = 16, l2_target: int | None = None, count_override: int | None = None,
                  data_rva: int | None = None) -> bytes:
    root = directory([(type_id, 0x80000000 | 0x18)])
    if count_override is not None:
        root = struct.pack('<IIHHHH', 0, 0, 0, 0, 0, count_override) + root[16:]
    level2 = directory([(1, 0x80000000 | (0x30 if l2_target is None else l2_target))])
    level3 = directory([(0x409, 0x48)])
    entry = struct.pack('<IIII', RSRC_RVA + 0x60 if data_rva is None else data_rva, len(blob), 0, 0)
    tree = root + level2 + level3 + entry
    tree += b'\0' * (0x60 - len(tree))
    return tree + blob


def pe_with(resource: bytes | None, *, rsds=(GUID, 3, r'd:\build\obj\amd64\netstack.pdb')) -> bytes:
    sections = [SectionSpec()]
    extra = {}
    if resource is not None:
        sections.append(SectionSpec('.rsrc', resource, RDATA))
        extra[2] = (RSRC_RVA, len(resource))
    return build_pe(PeSpec(sections=sections, rsds=rsds, extra_directories=extra))


def identity_of(tmp_path: Path, image: bytes, side: str = 'newer'):
    path = tmp_path / f'{side}.bin'
    path.write_bytes(image)
    with VerifiedArtifactReader.open_path(path) as reader:
        return idt.identity_from_reader(side, reader, asserted_product_ids=['PT-2', 'PT-1', 'PT-2'])


def test_versions_and_pdb_identity_come_from_verified_bytes(tmp_path):
    blob = version_blob(10 << 16, (22621 << 16) | 4036, 10 << 16, (22621 << 16) | 4037)
    identity = identity_of(tmp_path, pe_with(resource_tree(blob)))
    assert (identity.file_version, identity.product_version) == ('10.0.22621.4036', '10.0.22621.4037')
    assert identity.pdb_identity.name == 'netstack.pdb'  # base name only; the build path is not kept
    assert identity.pdb_identity.guid == '03020100050407060809' + '0A0B0C0D0E0F' and identity.pdb_identity.age == 3
    assert identity.facts_state == 'verified-bytes' and identity.asserted_product_ids == ('PT-1', 'PT-2')
    assert identity.notes == ()


def test_pe_without_resources_or_codeview(tmp_path):
    identity = identity_of(tmp_path, pe_with(None, rsds=None))
    assert identity.file_version is None and identity.pdb_identity is None
    assert identity.notes == ('no resource directory', 'no CodeView PDB identity')


@pytest.mark.parametrize('resource, note', [
    (resource_tree(version_blob(1, 2, 3, 4), type_id=3), 'no version resource'),
    (resource_tree(version_blob(1, 2, 3, 4, signature=0xDEADBEEF)), 'signature mismatch'),
    (resource_tree(version_blob(1, 2, 3, 4, key='VS_VERSION_INFX\0')), 'key missing'),
    (resource_tree(version_blob(1, 2, 3, 4, value_length=0)), 'no fixed file info'),
    (resource_tree(version_blob(1, 2, 3, 4), l2_target=0x18), 'no usable resource entry'),  # self loop
    (resource_tree(version_blob(1, 2, 3, 4), l2_target=0x7FFF0000), 'outside the resource directory'),
    (resource_tree(version_blob(1, 2, 3, 4), count_override=0xFFFF), 'outside the resource directory'),
    (resource_tree(version_blob(1, 2, 3, 4), data_rva=0x7FFFF000), 'not backed'),
    (resource_tree(version_blob(1, 2, 3, 4))[:0x50], 'outside the resource directory'),
])
def test_hostile_or_malformed_resources_degrade_to_a_note(tmp_path, resource, note):
    identity = identity_of(tmp_path, pe_with(resource))
    assert identity.file_version is None and identity.product_version is None
    assert any(note in n for n in identity.notes), identity.notes


def test_cancellation(tmp_path):
    path = tmp_path / 'x.bin'
    path.write_bytes(pe_with(None))
    cancel = threading.Event()
    cancel.set()
    with VerifiedArtifactReader.open_path(path) as reader, pytest.raises(IntelError) as info:
        idt.identity_from_reader('older', reader, cancel=cancel)
    assert info.value.code == 'PT-INTEL-CANCEL'


def test_project_identities_degrade_one_side_to_record_only(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as service:
        artifacts, root = service.project.artifacts, service.root
        older, newer = idt.project_identities(artifacts, root, {'newer': ['PT-900']})
        assert (older.facts_state, newer.facts_state) == ('verified-bytes', 'verified-bytes')
        assert newer.asserted_product_ids == ('PT-900',)
        target = next(a for a in artifacts if a.side == 'older')
        (root / target.relative_path).chmod(0o600)
        (root / target.relative_path).write_bytes(b'tampered')
        older, newer = idt.project_identities(artifacts, root)
        assert older.facts_state == 'record-only' and older.sha256 == target.sha256
        assert 'hash_mismatch' in older.notes[0] or 'size_mismatch' in older.notes[0]
        assert newer.facts_state == 'verified-bytes'
        assert target.name not in older.model_dump_json()  # the file name is never an identity fact
