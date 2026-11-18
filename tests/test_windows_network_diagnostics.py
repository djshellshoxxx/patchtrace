"""Real standard-C formatter controls; static boundaries do not simulate Windows APIs."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_windows_bindiff_network import NONCE, SID, chain
from tools import windows_bindiff_network as network

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'tools/windows_network'
BEGIN, END = '/* PT_DIAGNOSTIC_PORTABLE_BEGIN */', '/* PT_DIAGNOSTIC_PORTABLE_END */'
KEYS = {'diagnostic', 'sequence', 'stage', 'kind', 'owner_pid', 'subject_pid',
        'error', 'socket_index', 'sent_bytes', 'received_bytes'}
HARNESS = r'''
int main(int argc, char **argv) {
    unsigned int i;
    if (argc == 3 && strcmp(argv[1], "failed-write") == 0) {
        /* A valid read-only FILE rejects real stdio writes without a fake sink. */
        if (!freopen(argv[2], "r", stderr)) return 3;
        for (i = 0; i < 1000; ++i)
            pt_diag_emit(PT_DG_CHILD_SPAWN, PT_DK_WIN32, 1, 2, 5, UINT32_MAX, 0, 0);
        return pt_diag_count == 16 && ferror(stderr) ? 0 : 4;
    }
    if (argc != 2) return 2;
    if (strcmp(argv[1], "max") == 0) {
        pt_diag_emit(PT_DG_SOCKET_RECEIVE_WAIT, PT_DK_WINSOCK, UINT32_MAX, UINT32_MAX,
                     UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX);
    } else if (strcmp(argv[1], "invalid") == 0) {
        pt_diag_emit((PT_DIAG_STAGE)UINT32_MAX, (PT_DIAG_KIND)UINT32_MAX,
                     1, 2, 3, UINT32_MAX, 0, 0);
    } else if (strcmp(argv[1], "stages") == 0) {
        for (i = 0; i < PT_DG_COUNT; ++i) {
            pt_diag_count = 0; /* Independent formatter states, not the budget stress mode. */
            pt_diag_emit((PT_DIAG_STAGE)i, PT_DK_VALIDATION, 1, 2, 0, UINT32_MAX, 0, 0);
        }
    } else if (strcmp(argv[1], "kinds") == 0) {
        for (i = 0; i < PT_DK_COUNT; ++i) {
            pt_diag_count = 0;
            pt_diag_emit(PT_DG_UNKNOWN, (PT_DIAG_KIND)i, 1, 2, 0, UINT32_MAX, 0, 0);
        }
    } else if (strcmp(argv[1], "budget") == 0) {
        for (i = 0; i < 1000; ++i)
            pt_diag_emit(PT_DG_CHILD_SPAWN, PT_DK_WIN32, 1, 2, 5, UINT32_MAX, 0, 0);
    } else return 2;
    return 0;
}
'''


@pytest.fixture(scope='module')
def formatter(tmp_path_factory):
    text = (NATIVE / 'common.h').read_text(encoding='utf-8')
    assert text.count(BEGIN) == text.count(END) == 1, 'the real portable formatter section is absent'
    block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    # Only the real standard-C formatting code is compiled. No Windows API is
    # replaced with a fake success, and none of the downloaded EXEs is used.
    assert not any(name in block for name in ('CreateProcess', 'GetLastError', 'GetCurrentProcessId'))
    compiler = shutil.which('cc')
    if compiler is None:
        pytest.skip('portable C compiler unavailable; this does not qualify Windows')
    directory = tmp_path_factory.mktemp('native-diagnostic-formatter')
    source, binary = directory / 'formatter.c', directory / 'formatter-check'
    source.write_text('#include <stdio.h>\n#include <stdint.h>\n#include <string.h>\n'
                      + block + HARNESS, encoding='utf-8')
    env = {'PATH': os.defpath, 'LANG': 'C', 'LC_ALL': 'C'}
    result = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', str(source),
                             '-o', str(binary)], capture_output=True, timeout=20, env=env, check=False)
    assert result.returncode == 0, result.stderr.decode('utf-8', errors='replace')[:4000]

    def invoke(mode):
        argv = [str(binary), mode, *([str(source)] if mode == 'failed-write' else [])]
        result = subprocess.run(argv, capture_output=True, timeout=5, env=env, check=False)
        assert result.returncode == 0 and not result.stdout
        assert len(result.stderr) < 65536
        lines = result.stderr.splitlines()
        assert all(0 < len(line) < 512 for line in lines)
        records = [json.loads(line) for line in lines]
        for record in records:
            assert set(record) == KEYS and record['diagnostic'] == 'windows-network-diagnostic/1'
            for key in KEYS - {'diagnostic', 'stage', 'kind'}:
                assert type(record[key]) is int and 0 <= record[key] <= 2**32 - 1
            assert 1 <= record['sequence'] <= 16
            assert re.fullmatch(r'[a-z-]{1,32}', record['stage'])
            assert re.fullmatch(r'[a-z][a-z0-9-]{0,31}', record['kind'])
        return records, result.stderr

    return invoke


def test_real_formatter_keeps_maximum_numeric_values_bounded(formatter):
    rows, _raw = formatter('max')
    assert len(rows) == 1 and rows[0]['sequence'] == 1
    assert rows[0]['stage'] == 'socket-receive-wait' and rows[0]['kind'] == 'winsock'
    assert all(rows[0][name] == 2**32 - 1 for name in
               ('owner_pid', 'subject_pid', 'error', 'socket_index', 'sent_bytes', 'received_bytes'))


def test_real_formatter_has_fixed_vocabulary_and_safe_unknown_indices(formatter):
    stages, _ = formatter('stages')
    names = {row['stage'] for row in stages}
    assert len(names) == len(stages)
    assert {'process-create', 'job-assign', 'child-spawn', 'child-resume', 'child-finish',
            'socket-connect-wait', 'socket-send-wait', 'socket-receive-wait',
            'startup-terminate', 'startup-wait', 'diagnostic-limit'} <= names
    kinds, _ = formatter('kinds')
    assert {row['kind'] for row in kinds} == {
        'unknown', 'win32', 'winsock', 'validation', 'timeout', 'child-exit', 'wait-result', 'truncated'}
    invalid, _ = formatter('invalid')
    assert invalid[0]['stage'] == invalid[0]['kind'] == 'unknown'


def test_real_formatter_caps_total_records_and_marks_truncation_once(formatter):
    rows, raw = formatter('budget')
    assert len(rows) == 16 and len(raw) < 16 * 512
    assert [row['sequence'] for row in rows] == list(range(1, 17))
    assert all(row['stage'] == 'child-spawn' for row in rows[:-1])
    assert rows[-1]['stage'] == 'diagnostic-limit' and rows[-1]['kind'] == 'truncated'


def test_real_formatter_consumes_budget_when_stdio_writes_fail(formatter):
    rows, raw = formatter('failed-write')
    assert rows == [] and raw == b''


def test_static_win32_diagnostic_boundary_captures_and_restores_last_error():
    text = (NATIVE / 'common.h').read_text(encoding='utf-8')
    assert 'void pt_diag_win32(' in text, 'native error capture boundary is absent'
    body = text.split('void pt_diag_win32(', 1)[1].split('\n}', 1)[0]
    assert body.index('GetLastError()') < body.index('pt_diag_emit(') < body.index('SetLastError(')
    spawn = text.split('BOOL pt_spawn(', 1)[1].split('BOOL pt_finish(', 1)[0]
    assert 'pt_diag_win32(PT_DG_PROCESS_CREATE' in spawn
    assert 'pt_diag_win32(PT_DG_JOB_ASSIGN' in spawn
    assert 'pt_diag_validation(PT_DG_TOKEN_MATCH' in spawn


def test_static_socket_and_descendant_boundaries_retain_failure_context():
    text = (NATIVE / 'probe.c').read_text(encoding='utf-8')
    case = text.split('int socket_case(', 1)[1].split('int wmain(', 1)[0]
    assert 'pt_diag_emit(' in case, 'socket error phase/count capture is absent'
    assert case.index('pt_diag_emit(') < case.index('closesocket(stream)')
    assert 'PT_DG_SOCKET_CONNECT_WAIT' in case and 'PT_DG_SOCKET_RECEIVE_WAIT' in case
    descendant = text.split('if (depth < 2)', 1)[1]
    assert 'PT_DG_CHILD_SPAWN' in descendant and 'PT_DG_CHILD_FINISH' in descendant
    assert descendant.index('PT_DG_CHILD_RESUME') < descendant.index('TerminateJobObject')


def test_diagnostic_stderr_cannot_turn_exit_125_into_completion():
    result = SimpleNamespace(reason=None, returncode=125,
                             stderr_tail='{"diagnostic":"windows-network-diagnostic/1","error":5}')
    with pytest.raises(network.NetworkEvidenceError):
        network._completed(result, 'restricted control process chain')


@pytest.mark.parametrize('incomplete', [False, True])
def test_diagnostics_cannot_credit_timeout_or_incomplete_process_chain(incomplete):
    rows = chain(True)
    rows[0]['diagnostics'] = {'kind': 'timeout', 'stage': 'socket-connect-wait'}
    if incomplete:
        rows = rows[:1]
    else:
        rows[0]['cases'][0].update(status='error', error=10060)
    with pytest.raises(network.NetworkEvidenceError):
        network._probe_chain(rows, sid=SID, nonce=NONCE, blocked=True)
