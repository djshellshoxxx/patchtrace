"""Authored PW-02 data; these records are not native FDI or authenticity receipts."""
from __future__ import annotations

import importlib

A, B, C, D = (character * 64 for character in 'abcd')


def contracts():
    return importlib.import_module('patchtrace.acquisition.package_contracts')


def source(**changes):
    c = contracts()
    values = dict(sha256=A, size=128, display_name='authored.cab',
                  file_identity=c.PackageFileIdentity(volume_serial=7, file_id='1' * 32,
                                                      size=128, last_write_ticks=10),
                  source_claims=('authored contract fixture; no native verification',))
    values.update(changes)
    return c.PackageSource(**values)


def decoder():
    return contracts().PackageDecoder(dll_sha256=D, dll_version='1.2.3.4',
                                       os_version='authored Windows fixture', probe_state='passed')


def part(*, name=b'sample.dll', utf8=False, container=A, ancestors=(), ordinal=1,
         state='header-only', kind='fullfile', basis='filename-hint', size=4, **changes):
    c = contracts()
    paths = importlib.import_module('patchtrace.acquisition.package_paths')
    logical = paths.decode_member_name(name, utf8=utf8).path
    values = dict(container_sha256=container, ancestors=ancestors, ordinal=ordinal,
                  raw_name_hex=name.hex(), name_utf8=utf8, logical_path=logical,
                  declared_size=size, compressed_size=None, kind=kind, kind_basis=basis,
                  content_state=state)
    if state != 'header-only':
        values.update(observed_size=size, observed_sha256=B)
    if state == 'reverified':
        values['rehash_sha256'] = B
    if kind == 'fullfile' and basis == 'content':
        values['machine'] = 34404
    values.update(changes)
    values['member_id'] = c.member_identity(values['container_sha256'], values['ancestors'],
                                           values['ordinal'], values['raw_name_hex'], values['name_utf8'])
    return c.PackagePart(**values)


def inventory(*, parts=(), containers=None, mode='headers', complete=True, **changes):
    c = contracts()
    original = source()
    if containers is None:
        containers = (c.PackageContainer(container_sha256=original.sha256, ancestors=(),
                                         size=original.size, entry_count=len(parts), complete=True),)
    values = dict(contract='local-package/1', parser_version=1, source=original, decoder=decoder(),
                  mode=mode, limits=c.PackageLimits(), parts=tuple(parts), containers=tuple(containers),
                  complete=complete, diagnostics=())
    values.update(changes)
    return c.PackageInventory(inventory_id=c.inventory_identity(values), **values)


def selection(inv, member, **changes):
    values = dict(inventory_id=inv.inventory_id, source_sha256=inv.source.sha256,
                  member_id=member.member_id, ancestors=member.ancestors, side='older',
                  expected_basename='sample.dll', expected_sha256=None)
    values.update(changes)
    return contracts().PackageSelection(**values)
