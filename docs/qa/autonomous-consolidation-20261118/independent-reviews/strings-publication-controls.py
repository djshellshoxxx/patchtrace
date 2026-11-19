from __future__ import annotations
import errno
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
import pytest
from patchtrace.strings import export
from patchtrace.strings.contracts import StringsError

@pytest.mark.parametrize('kind',['symlink','directory'])
def test_late_other_destination_survives(tmp_path,monkeypatch,kind):
    target=tmp_path/'report.json';outside=tmp_path/'prior';outside.write_bytes(b'prior')
    real_sync=os.fsync
    def sync(fd):
        real_sync(fd)
        target.symlink_to(outside) if kind=='symlink' else target.mkdir()
    monkeypatch.setattr(export.os,'fsync',sync)
    with pytest.raises(StringsError):export.write_atomic(target,b'new',force=False)
    assert outside.read_bytes()==b'prior'
    assert target.is_symlink() if kind=='symlink' else target.is_dir()
    assert set(tmp_path.iterdir())=={target,outside}

def test_two_writers_have_independent_stages_and_only_one_wins(tmp_path,monkeypatch):
    target=tmp_path/'report.json';barrier=Barrier(2);real_sync=os.fsync
    def sync(fd):real_sync(fd);barrier.wait(timeout=5)
    monkeypatch.setattr(export.os,'fsync',sync)
    def write(data):
        try:export.write_atomic(target,data,force=False);return ('ok',data)
        except StringsError:return ('refused',data)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(write,[b'A'*300000,b'B'*300000]))
    assert sorted(x[0] for x in results)==['ok','refused']
    assert target.read_bytes()==next(data for status,data in results if status=='ok')
    assert list(tmp_path.iterdir())==[target]

def test_force_replaces_link_not_referent(tmp_path):
    target=tmp_path/'report.json';outside=tmp_path/'prior';outside.write_bytes(b'prior');target.symlink_to(outside)
    export.write_atomic(target,b'new',force=True)
    assert target.read_bytes()==b'new' and not target.is_symlink()
    assert outside.read_bytes()==b'prior'

def test_unsupported_exclusive_publish_does_not_fall_back(tmp_path,monkeypatch):
    def unsupported(*a,**k):raise OSError(errno.ENOTSUP,'unsupported')
    def replace(*a,**k):raise AssertionError('replacement must not be attempted')
    monkeypatch.setattr(export.os,'link',unsupported);monkeypatch.setattr(export.os,'replace',replace)
    with pytest.raises(StringsError) as caught:export.write_atomic(tmp_path/'report.json',b'new',force=False)
    assert caught.value.code=='PT-STR-EXPORT' and list(tmp_path.iterdir())==[]

def test_fdopen_failure_closes_untransferred_descriptor(tmp_path,monkeypatch):
    captured=[]
    def refuse(fd,*a,**k):captured.append(fd);raise OSError(errno.EACCES,'fdopen refused')
    monkeypatch.setattr(export.os,'fdopen',refuse)
    with pytest.raises(StringsError):export.write_atomic(tmp_path/'report.json',b'new',force=False)
    assert len(captured)==1
    with pytest.raises(OSError) as caught:os.fstat(captured[0])
    assert caught.value.errno==errno.EBADF and list(tmp_path.iterdir())==[]

def test_sync_error_preserves_unowned_similar_stage(tmp_path,monkeypatch):
    prior=tmp_path/'.report.json.other.tmp';prior.write_bytes(b'prior')
    def refuse(fd):raise OSError(errno.EIO,'sync failure')
    monkeypatch.setattr(export.os,'fsync',refuse)
    with pytest.raises(StringsError):export.write_atomic(tmp_path/'report.json',b'new',force=False)
    assert list(tmp_path.iterdir())==[prior] and prior.read_bytes()==b'prior'

@pytest.mark.parametrize('force',[False,True])
def test_preexisting_regular_old_stage_is_never_reused(tmp_path,force):
    target=tmp_path/'report.json';prior=tmp_path/f'.report.json.{os.getpid()}.tmp';prior.write_bytes(b'prior')
    export.write_atomic(target,b'new',force=force)
    assert target.read_bytes()==b'new' and prior.read_bytes()==b'prior'
    assert set(tmp_path.iterdir())=={target,prior}
