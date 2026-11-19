"""Publication receipts reject observed same-inode edits with bounded reads."""
from __future__ import annotations

import os
import sys

import pytest

from patchtrace import owned_publication as owned


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux descriptor-link publication')
@pytest.mark.parametrize('replacement', [b'foreign content', b'longer foreign bytes', b''])
def test_no_replace_publication_never_credits_same_inode_edits_after_link(tmp_path, monkeypatch, replacement):
    target = tmp_path / 'new-object'
    prior = tmp_path / 'prior-object'
    prior.write_bytes(b'preserve prior evidence')
    link = os.link

    def mutate(source, destination, **kwargs):
        link(source, destination, **kwargs)
        before = target.stat()
        target.write_bytes(replacement)
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert target.stat().st_ino == before.st_ino

    monkeypatch.setattr(os, 'link', mutate)
    with pytest.raises(owned.OwnedPublicationError, match='bytes changed'):
        owned.publish_bytes(target, b'expected export')
    assert target.read_bytes() == replacement  # no unsafe pathname rollback
    assert prior.read_bytes() == b'preserve prior evidence'


def test_held_source_verifier_bounds_reads_if_source_grows_during_read(tmp_path, monkeypatch):
    data = b'expected export'
    target = tmp_path / 'source'
    target.write_bytes(data)
    descriptor = os.open(target, os.O_RDWR)
    identity = owned.file_identity(os.fstat(descriptor))
    fdopen = os.fdopen
    reads = []

    class GrowingReader:
        def __enter__(self):
            self.handle = fdopen(descriptor, 'rb', buffering=0, closefd=False)
            return self

        def __exit__(self, *args):
            self.handle.close()

        def seek(self, offset):
            return self.handle.seek(offset)

        def read(self, count):
            reads.append(count)
            result = self.handle.read(count)
            if len(reads) == 1:
                os.ftruncate(descriptor, 256 * 1024 * 1024)
            return result

    def observed_open(fd, mode, *, buffering, closefd):
        assert fd == descriptor and mode == 'rb' and buffering == 0 and closefd is False
        return GrowingReader()

    monkeypatch.setattr(os, 'fdopen', observed_open)
    try:
        with pytest.raises(owned.OwnedPublicationError, match='bytes changed'):
            owned.verify_stage(descriptor, data, identity)
        assert reads == [len(data), 1]
    finally:
        os.close(descriptor)


def test_held_source_verifier_rejects_oversized_source_before_reading(tmp_path, monkeypatch):
    target = tmp_path / 'source'
    target.write_bytes(b'longer than expected')
    descriptor = os.open(target, os.O_RDONLY)

    def refuse_open(*args, **kwargs):
        pytest.fail('oversized source must be rejected before reads')

    monkeypatch.setattr(os, 'fdopen', refuse_open)
    try:
        with pytest.raises(owned.OwnedPublicationError, match='bytes changed'):
            owned.verify_stage(descriptor, b'expected', owned.file_identity(os.fstat(descriptor)))
    finally:
        os.close(descriptor)
