"""Authored portable held-reader provider; never evidence for Windows sharing."""
from __future__ import annotations

import builtins
import io
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from patchtrace.ingestion import CHUNK_SIZE
from patchtrace.sample import synthetic_pe


class ReadStopped(ValueError):
    pass


class Checkpoint:
    def __init__(self):
        self.counts = []
        self.kind = 'core'
        self.stop = lambda count, kind: False
        self.reserved_output = 123456  # Separate extraction allowance; core must not change it.

    def __call__(self, count):
        assert type(count) is int and 0 <= count <= CHUNK_SIZE
        self.counts.append((self.kind, count))
        if self.stop(count, self.kind):
            raise ReadStopped('authored operation stopped')


def state(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


class HeldFile:
    def __init__(self, path, checkpoint):
        self.path, self.checkpoint = Path(path), checkpoint
        self.fd = os.open(self.path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        self.captured = state(os.fstat(self.fd))
        self.active = False
        self.opened = self.closed = self.checks = 0
        self.bytes_read = 0
        self.changed = False
        self.on_read = lambda: None
        self.read_limit = None

    def check(self, path):
        self.checkpoint(0)
        self.checks += 1
        if Path(path) != self.path or self.changed or state(os.fstat(self.fd)) != self.captured:
            raise ReadStopped('authored held identity changed')

    @contextmanager
    def open_reader(self, path):
        self.check(path)
        assert not self.active
        self.active = True
        self.opened += 1
        try:
            with os.fdopen(os.dup(self.fd), 'rb') as raw:
                raw.seek(0)  # POSIX fake is serial; a native adapter must supply its own verified open.
                owner = self

                class Reader:
                    def fileno(self):
                        return raw.fileno()

                    def read(self, size):
                        assert type(size) is int and 0 <= size <= CHUNK_SIZE
                        prior, owner.checkpoint.kind = owner.checkpoint.kind, 'held'
                        try:
                            owner.checkpoint(0)
                            data = raw.read(size if owner.read_limit is None else min(size, owner.read_limit))
                            owner.bytes_read += len(data)
                            owner.checkpoint(len(data))
                            owner.on_read()
                            return data
                        finally:
                            owner.checkpoint.kind = prior

                    def seek(self, offset):
                        owner.checkpoint(0)
                        assert 0 <= offset <= owner.captured[2]
                        return raw.seek(offset)

                yield Reader()
                self.check(path)
        finally:
            self.closed += 1
            self.active = False

    def close(self):
        os.close(self.fd)


@contextmanager
def authored_pair(tmp_path, *, padding=0):
    checkpoint = Checkpoint()
    paths, leases = [], []
    for side, variant in (('older', 0), ('newer', 1)):
        path = tmp_path / side / 'example.sys'
        path.parent.mkdir(parents=True)
        path.write_bytes(synthetic_pe(variant) + b'P' * padding)
        paths.append(path)
        leases.append(HeldFile(path, checkpoint))
    try:
        yield paths, SimpleNamespace(older=leases[0], newer=leases[1], checkpoint=checkpoint)
    finally:
        for lease in leases:
            lease.close()


def deny_source_opens(monkeypatch, paths):
    selected = {str(path) for path in paths}

    def guarded(real):
        def call(path, *args, **kwargs):
            if isinstance(path, (str, os.PathLike)) and str(path) in selected:
                raise AssertionError('selected held source was reopened by pathname')
            return real(path, *args, **kwargs)
        return call

    monkeypatch.setattr(builtins, 'open', guarded(builtins.open))
    monkeypatch.setattr(io, 'open', guarded(io.open))
    monkeypatch.setattr(os, 'open', guarded(os.open))
