"""Independent explicit-list failure sequencing; authored Win32 boundary only."""
from __future__ import annotations

import pytest
from test_jobs_windows_handles import PYTHON, SINK, SOURCE, fake_native

from patchtrace import jobs


@pytest.mark.parametrize('fault', ['query-success', 'query-wrong-error', 'update-failure'])
def test_no_child_if_attribute_contract_is_not_exact(tmp_path, monkeypatch, fault):
    kernel = fake_native(monkeypatch)
    if fault == 'update-failure':
        kernel.fail = 'UpdateProcThreadAttribute'
    else:
        original = kernel.call_InitializeProcThreadAttributeList
        def query(buffer, count, flags, size):
            result = original(buffer, count, flags, size)
            if buffer is None:
                if fault == 'query-success':
                    return 1
                kernel.error = 5
            return result
        kernel.call_InitializeProcThreadAttributeList = query
    with pytest.raises(OSError):
        jobs._windows_process([PYTHON], tmp_path, {}, True,
                              windows_borrowed_handles=(('SOURCE', SOURCE), ('SINK', SINK)))
    assert not kernel.records
    assert kernel.flags == {SOURCE: 0, SINK: 1}
    assert not jobs._WINDOWS_SPAWN_LOCK.locked()
    assert kernel.count['DeleteProcThreadAttributeList'] == (1 if fault == 'update-failure' else 0)


def test_approval_list_and_environment_live_until_create_and_retire_before_unlock(tmp_path, monkeypatch):
    kernel = fake_native(monkeypatch)
    original = kernel.call_CreateProcessW
    def inspect(*args):
        result = original(*args)
        listed = kernel.records[-1]['handles']
        assert all(handle in kernel.flags and kernel.flags[handle] & 1 for handle in listed)
        assert all(handle not in kernel.closed for handle in listed)
        assert SOURCE not in listed and SINK not in listed
        return result
    kernel.call_CreateProcessW = inspect
    original_close = kernel.call_CloseHandle
    def close(handle):
        if kernel.number(handle) in {duplicate for _, duplicate in kernel.duplicates}:
            assert jobs._WINDOWS_SPAWN_LOCK.locked()
        return original_close(handle)
    kernel.call_CloseHandle = close
    child = jobs._windows_process([PYTHON], tmp_path, {'EXACT':'kept'}, True,
                                  windows_borrowed_handles=(('SOURCE', SOURCE), ('SINK', SINK)))
    child.stdout.close()
    child.stderr.close()
    child.close()
    assert set(kernel.closed) == set(kernel.created)
    assert kernel.flags == {SOURCE: 0, SINK: 1}


def test_closed_original_refuses_without_resume_or_original_close(tmp_path, monkeypatch):
    kernel = fake_native(monkeypatch)
    kernel.flags.pop(SINK)
    with pytest.raises(OSError):
        jobs._windows_process([PYTHON], tmp_path, {}, True,
                              windows_borrowed_handles=(('SOURCE', SOURCE), ('SINK', SINK)))
    assert 'ResumeThread' not in kernel.calls and not kernel.records
    assert SOURCE not in kernel.closed and SINK not in kernel.closed
    assert kernel.flags == {SOURCE: 0}
    assert set(kernel.closed) == set(kernel.created)
