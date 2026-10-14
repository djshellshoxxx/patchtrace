"""C4 consumes C3's real `accept_binexport` through `cli_bindiff.c3_acceptor` (frozen seam, binexport2-support §4).

Runs the real capped worker on the synthetic fixtures; no BinDiff executable is involved and the fixtures are
not live-compatibility evidence (tests/fixtures/binexport/PROVENANCE.json).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from patchtrace.secondary.bindiff_inputs import AcceptedBinExportLike, bind_pair
from patchtrace.secondary.cli_bindiff import c3_acceptor
from patchtrace.secondary.contracts import SecondaryError

FIXTURES = Path(__file__).parent / 'fixtures' / 'binexport'
_PROVENANCE = {item['file']: item for item in json.loads((FIXTURES / 'PROVENANCE.json').read_text())['fixtures']}
OLDER_FILE, NEWER_FILE = FIXTURES / 'synthetic-older.BinExport', FIXTURES / 'synthetic-newer.BinExport'
OLDER_SHA = _PROVENANCE['synthetic-older.BinExport']['source_sha256']
NEWER_SHA = _PROVENANCE['synthetic-newer.BinExport']['source_sha256']


@pytest.fixture
def acceptor(tmp_path):
    accept = c3_acceptor(tmp_path / 'private')
    assert accept is not None, 'the BinExport2 runtime must be importable in the test environment'
    return accept


def _accept(accept, path: Path, role: str, artifact: str, other: str):
    return accept(path, artifact_sha256=artifact, role=role, accept_unbound=False, cancel=threading.Event(),
                  other_sha256=other)


def test_real_acceptor_output_satisfies_the_c4_protocol_and_binds_the_pair(acceptor):
    older = _accept(acceptor, OLDER_FILE, 'older', OLDER_SHA, NEWER_SHA)
    newer = _accept(acceptor, NEWER_FILE, 'newer', NEWER_SHA, OLDER_SHA)
    assert isinstance(older, AcceptedBinExportLike) and isinstance(newer, AcceptedBinExportLike)
    assert older.snapshot_path != OLDER_FILE and older.snapshot_path.is_file()  # C4 must use the snapshot
    bound = bind_pair(older, newer, OLDER_SHA, NEWER_SHA)
    assert not bound.asserted
    assert bound.expected_file_hashes() == (OLDER_SHA, NEWER_SHA)


def test_swapped_files_are_reported_as_orientation_errors(acceptor):
    with pytest.raises(SecondaryError) as info:
        _accept(acceptor, NEWER_FILE, 'older', OLDER_SHA, NEWER_SHA)
    assert info.value.code == 'PT-SECONDARY-ORIENTATION'
    assert info.value.kind == 'binexport-orientation'


def test_export_of_a_foreign_artifact_is_a_pair_error(acceptor):
    with pytest.raises(SecondaryError) as info:
        _accept(acceptor, OLDER_FILE, 'older', '0' * 64, '1' * 64)
    assert info.value.code == 'PT-SECONDARY-PAIR'
