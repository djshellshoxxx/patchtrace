"""Authored C control-flow tests with scripted APIs, never native Windows evidence.

The legacy selector is the exact old NUL-open fragment, not a Python rewrite.
The repaired selector/lease functions are extracted verbatim from common.h.
The surrogate types deliberately do not validate the Windows SDK or ABI.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'tools/windows_network'
BEGIN, END = '/* PT_STDIN_PORTABLE_BEGIN */', '/* PT_STDIN_PORTABLE_END */'
PRELUDE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *PSID;
typedef int PT_DIAG_STAGE;
#define WINAPI
/* This surrogate signature is not the SDK FARPROC or an ABI qualification. */
typedef BOOL (*FARPROC)(HANDLE, HANDLE);
typedef struct { DWORD nLength; void *lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES;
typedef struct { DWORD dwFlags; HANDLE hStdInput; } STARTUPINFOW;
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_INVALID_DATA 13
#define INVALID_HANDLE_VALUE ((HANDLE)(uintptr_t)-1)
#define STD_INPUT_HANDLE ((DWORD)-10)
#define STARTF_USESTDHANDLES 0x100
#define FILE_TYPE_UNKNOWN 0
#define FILE_TYPE_DISK 1
#define FILE_TYPE_CHAR 2
#define FILE_TYPE_PIPE 3
#define HANDLE_FLAG_INHERIT 1
#define HANDLE_FLAG_PROTECT_FROM_CLOSE 2
#define DUPLICATE_SAME_ACCESS 2
#define GENERIC_READ 0x80000000u
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define OPEN_EXISTING 3
#define FILE_ATTRIBUTE_NORMAL 0x80
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x800
#define ZeroMemory(p,n) memset((p), 0, (n))
typedef struct { int object, open, owned, attempts; DWORD type, flags; } OBJECT;
OBJECT objects[128];
DWORD last_error, startup_flags = STARTF_USESTDHANDLES;
HANDLE current_input = (HANDLE)(uintptr_t)10, startup_input = (HANDLE)(uintptr_t)11;
int next_handle = 20, load_calls, export_calls, duplicate_calls, nul_calls, close_calls, free_calls;
int bad_arguments, borrowed_close, stale_close, diagnostics, module_live;
int deny_nul, fail_load, fail_export, fail_duplicate, fail_close, fail_free, fail_flags;
int bad_type_duplicate, bad_flags_duplicate, bad_object_duplicate, race_after_duplicate;
int nul_pipe, nul_flags, unknown_error;
DWORD bad_flags_value = HANDLE_FLAG_INHERIT;
int id(HANDLE h) { uintptr_t v = (uintptr_t)h; return v < 128 ? (int)v : 0; }
DWORD GetLastError(void) { return last_error; }
void SetLastError(DWORD value) { last_error = value; }
HANDLE GetCurrentProcess(void) { return (HANDLE)(uintptr_t)999; }
void pt_diag_win32(PT_DIAG_STAGE stage, DWORD subject) { (void)stage; (void)subject; ++diagnostics; }
void pt_diag_validation(PT_DIAG_STAGE stage, DWORD subject) { (void)stage; (void)subject; ++diagnostics; }
HANDLE GetStdHandle(DWORD which) { if (which != STD_INPUT_HANDLE) ++bad_arguments; return current_input; }
void GetStartupInfoW(STARTUPINFOW *out) { out->dwFlags = startup_flags; out->hStdInput = startup_input; }
DWORD GetFileType(HANDLE handle) {
    int h = id(handle);
    if (!h || !objects[h].open) { last_error = 707; return FILE_TYPE_UNKNOWN; }
    if (!objects[h].type) last_error = (DWORD)unknown_error;
    return objects[h].type;
}
BOOL GetHandleInformation(HANDLE handle, DWORD *flags) {
    int h = id(handle);
    if (fail_flags || !h || !objects[h].open) { last_error = 706; return FALSE; }
    *flags = objects[h].flags; return TRUE;
}
BOOL compare_objects(HANDLE first, HANDLE second) {
    int a = id(first), b = id(second);
    last_error = 933; /* A rejected identity must set a deterministic validation error. */
    return a && b && objects[a].open && objects[b].open && objects[a].object == objects[b].object;
}
HMODULE LoadLibraryExW(const wchar_t *name, HANDLE file, DWORD flags) {
    ++load_calls;
    if (wcscmp(name, L"kernelbase.dll") || file || flags != LOAD_LIBRARY_SEARCH_SYSTEM32) ++bad_arguments;
    if (fail_load) { last_error = 701; return NULL; }
    ++module_live; return (HMODULE)(uintptr_t)200;
}
FARPROC GetProcAddress(HMODULE module, const char *name) {
    ++export_calls;
    if (module != (HMODULE)(uintptr_t)200 || !module_live || strcmp(name, "CompareObjectHandles")) ++bad_arguments;
    if (fail_export) { last_error = 702; return NULL; }
    return compare_objects;
}
BOOL FreeLibrary(HMODULE module) {
    ++free_calls;
    if (module != (HMODULE)(uintptr_t)200 || module_live != 1) ++bad_arguments;
    if (fail_free) { last_error = 709; return FALSE; }
    --module_live; last_error = 912; return TRUE;
}
BOOL DuplicateHandle(HANDLE source_process, HANDLE source, HANDLE destination_process,
                     HANDLE *out, DWORD access, BOOL inherit, DWORD options) {
    int h = id(source), created;
    ++duplicate_calls;
    if (source_process != GetCurrentProcess() || destination_process != GetCurrentProcess() ||
        access != 0 || options != DUPLICATE_SAME_ACCESS || (inherit != FALSE && inherit != TRUE)) ++bad_arguments;
    if (duplicate_calls == fail_duplicate) { last_error = 600 + (DWORD)duplicate_calls; return FALSE; }
    if (!h || !objects[h].open || next_handle >= 100) { last_error = 707; return FALSE; }
    created = next_handle++;
    objects[created] = objects[h]; objects[created].owned = 1; objects[created].attempts = 0;
    objects[created].flags = inherit ? HANDLE_FLAG_INHERIT : 0;
    if (duplicate_calls == bad_type_duplicate) objects[created].type = FILE_TYPE_PIPE;
    if (duplicate_calls == bad_flags_duplicate) objects[created].flags = bad_flags_value;
    if (duplicate_calls == bad_object_duplicate) objects[created].object = 77;
    *out = (HANDLE)(uintptr_t)created;
    if (duplicate_calls == race_after_duplicate) objects[10].object = 88;
    last_error = 913; return TRUE;
}
HANDLE CreateFileW(const wchar_t *name, DWORD access, DWORD share, SECURITY_ATTRIBUTES *security,
                   DWORD disposition, DWORD flags, HANDLE template_file) {
    int h;
    ++nul_calls;
    if (wcscmp(name, L"NUL") || access != GENERIC_READ || share != (FILE_SHARE_READ | FILE_SHARE_WRITE) ||
        !security || security->nLength != sizeof(*security) || security->lpSecurityDescriptor ||
        security->bInheritHandle != TRUE || disposition != OPEN_EXISTING ||
        flags != FILE_ATTRIBUTE_NORMAL || template_file) ++bad_arguments;
    if (deny_nul) { last_error = 5; return INVALID_HANDLE_VALUE; }
    h = next_handle++;
    objects[h] = (OBJECT){1, 1, 1, 0, nul_pipe ? FILE_TYPE_PIPE : FILE_TYPE_CHAR,
                           nul_flags ? HANDLE_FLAG_PROTECT_FROM_CLOSE : HANDLE_FLAG_INHERIT};
    last_error = 914; return (HANDLE)(uintptr_t)h;
}
BOOL CloseHandle(HANDLE handle) {
    int h = id(handle);
    ++close_calls;
    if (!h || !objects[h].owned) { ++borrowed_close; last_error = 707; return FALSE; }
    if (++objects[h].attempts > 1 || !objects[h].open) { ++stale_close; last_error = 707; return FALSE; }
    if (close_calls == fail_close) { last_error = 708; return FALSE; }
    objects[h].open = 0; last_error = 911; return TRUE;
}
void setup(void) {
    objects[10] = (OBJECT){1, 1, 0, 0, FILE_TYPE_CHAR, HANDLE_FLAG_INHERIT};
    objects[11] = objects[10]; last_error = 991;
}
'''

DRIVER = r'''
int main(int argc, char **argv) {
    PT_STDIN input = {0};
    HANDLE out = NULL;
    int result = 0, release_result = -1, second_release = -1, output_id, output_flags, output_object;
    int held_flags = -1, held_object = -1, empty;
    DWORD error = 0, release_error = 0;
    const char *mode;
    if (argc != 2) return 2;
    mode = argv[1]; setup();
    if (strncmp(mode, "select-", 7) == 0) {
        PSID sid = NULL;
        const PT_STDIN *provided = &input;
        objects[12] = (OBJECT){1, 1, 1, 0, FILE_TYPE_CHAR, 0};
        input.held = (HANDLE)(uintptr_t)12; input.comparison_module = (HMODULE)(uintptr_t)200;
        input.compare = compare_objects; module_live = 1;
        if (!strcmp(mode, "select-forward")) deny_nul = 1;
        else if (!strcmp(mode, "select-fresh")) { sid = (PSID)(uintptr_t)1; provided = NULL; }
        else if (!strcmp(mode, "select-nul-fails")) { sid = (PSID)(uintptr_t)1; provided = NULL; deny_nul = 1; }
        else if (!strcmp(mode, "select-neither")) provided = NULL;
        else if (!strcmp(mode, "select-both")) sid = (PSID)(uintptr_t)1;
        else if (!strcmp(mode, "select-fresh-pipe")) { sid = (PSID)(uintptr_t)1; provided = NULL; nul_pipe = 1; }
        else if (!strcmp(mode, "select-fresh-protected")) { sid = (PSID)(uintptr_t)1; provided = NULL; nul_flags = 1; }
        else if (!strcmp(mode, "select-cleanup-error")) {
            sid = (PSID)(uintptr_t)1; provided = NULL; nul_pipe = 1; fail_close = 1;
        } else return 2;
        result = pt_stdin_select(sid, provided, &out); error = GetLastError();
    } else {
#if PT_HAS_STDIN
        if (!strcmp(mode, "capture-load-fails")) fail_load = 1;
        else if (!strcmp(mode, "capture-export-fails")) fail_export = 1;
        else if (!strcmp(mode, "capture-export-cleanup-fails")) { fail_export = 1; fail_free = 1; }
        else if (!strcmp(mode, "capture-no-flag")) startup_flags = 0;
        else if (!strcmp(mode, "capture-current-null")) current_input = NULL;
        else if (!strcmp(mode, "capture-current-invalid")) current_input = INVALID_HANDLE_VALUE;
        else if (!strcmp(mode, "capture-startup-null")) startup_input = NULL;
        else if (!strcmp(mode, "capture-startup-invalid")) startup_input = INVALID_HANDLE_VALUE;
        else if (!strcmp(mode, "capture-pipe")) objects[10].type = FILE_TYPE_PIPE;
        else if (!strcmp(mode, "capture-disk")) objects[11].type = FILE_TYPE_DISK;
        else if (!strcmp(mode, "capture-unknown")) objects[10].type = FILE_TYPE_UNKNOWN;
        else if (!strcmp(mode, "capture-type-error")) { objects[10].type = FILE_TYPE_UNKNOWN; unknown_error = 705; }
        else if (!strcmp(mode, "capture-identity")) objects[11].object = 99;
        else if (!strcmp(mode, "capture-duplicate-fails")) fail_duplicate = 1;
        else if (!strcmp(mode, "capture-private-flags")) bad_flags_duplicate = 1;
        else if (!strcmp(mode, "capture-private-type")) bad_type_duplicate = 1;
        else if (!strcmp(mode, "capture-private-identity")) bad_object_duplicate = 1;
        else if (!strcmp(mode, "capture-race")) race_after_duplicate = 1;
        else if (!strcmp(mode, "capture-query-fails")) fail_flags = 1;
        else if (!strcmp(mode, "capture-validation-cleanup-fails")) { bad_object_duplicate = 1; fail_close = 1; fail_free = 1; }
        else if (strcmp(mode, "capture-ok") && strncmp(mode, "forward-", 8) && strncmp(mode, "release-", 8)) return 2;
        result = pt_stdin_capture(&input); error = GetLastError();
        if (result) {
            held_flags = (int)objects[id(input.held)].flags;
            held_object = objects[id(input.held)].object;
            if (strncmp(mode, "forward-", 8) == 0) {
                if (!strcmp(mode, "forward-replaced")) objects[10].object = 99;
                else if (!strcmp(mode, "forward-duplicate-fails")) fail_duplicate = 2;
                else if (!strcmp(mode, "forward-private-inherit")) objects[id(input.held)].flags = HANDLE_FLAG_INHERIT;
                else if (!strcmp(mode, "forward-private-protected")) objects[id(input.held)].flags = HANDLE_FLAG_PROTECT_FROM_CLOSE;
                else if (!strcmp(mode, "forward-copy-flags")) { bad_flags_duplicate = 2; bad_flags_value = 0; }
                else if (!strcmp(mode, "forward-copy-protected")) { bad_flags_duplicate = 2; bad_flags_value = 3; }
                else if (!strcmp(mode, "forward-copy-type")) bad_type_duplicate = 2;
                else if (!strcmp(mode, "forward-copy-identity")) bad_object_duplicate = 2;
                else if (!strcmp(mode, "forward-cleanup-fails")) { bad_object_duplicate = 2; fail_close = 1; }
                else if (!strcmp(mode, "forward-race")) race_after_duplicate = 2;
                else if (!strcmp(mode, "forward-occupied")) {
                    objects[30] = (OBJECT){3, 1, 1, 0, FILE_TYPE_CHAR, 0}; out = (HANDLE)(uintptr_t)30;
                } else if (strcmp(mode, "forward-ok")) return 2;
                result = pt_stdin_duplicate(&input, &out); error = GetLastError();
            } else if (strncmp(mode, "release-", 8) == 0) {
                if (!strcmp(mode, "release-close-fails")) fail_close = 1;
                else if (!strcmp(mode, "release-module-fails")) fail_free = 1;
                else if (!strcmp(mode, "release-both-fail")) { fail_close = 1; fail_free = 1; }
                else if (strcmp(mode, "release-twice")) return 2;
            }
        }
#else
        puts("{\"missing_helpers\":true}"); return 0;
#endif
    }
    output_id = id(out); output_flags = (int)objects[output_id].flags; output_object = objects[output_id].object;
#if PT_HAS_STDIN
    if (strncmp(mode, "select-", 7)) {
        if (out && output_id != 30) { CloseHandle(out); out = NULL; }
        if (input.held || input.comparison_module || input.compare) {
            SetLastError(345); release_result = pt_stdin_release(&input); release_error = GetLastError();
            second_release = pt_stdin_release(&input);
        }
    }
#endif
    empty = !input.held && !input.comparison_module && !input.compare;
    printf("{\"result\":%d,\"error\":%u,\"release\":%d,\"release_error\":%u,\"second_release\":%d,"
           "\"nul\":%d,\"duplicates\":%d,\"loads\":%d,\"exports\":%d,\"closes\":%d,\"frees\":%d,"
           "\"bad_arguments\":%d,\"borrowed_close\":%d,\"stale_close\":%d,\"empty\":%d,"
           "\"output\":%d,\"output_flags\":%d,\"output_object\":%d,\"held_flags\":%d,\"held_object\":%d,"
           "\"external_open\":%d,\"diagnostics\":%d}\n",
           result, error, release_result, release_error, second_release, nul_calls, duplicate_calls,
           load_calls, export_calls, close_calls, free_calls, bad_arguments, borrowed_close, stale_close, empty,
           output_id, output_flags, output_object, held_flags, held_object, objects[30].open, diagnostics);
    return 0;
}
'''


def _tested_block(text: str) -> tuple[str, bool]:
    if BEGIN in text:
        assert text.count(BEGIN) == text.count(END) == 1
        return text.split(BEGIN, 1)[1].split(END, 1)[0], True
    # Preserve an executable pre-fix behavior control. Only the surrounding
    # test interface is supplied; the actual original NUL-open body is verbatim.
    spawn = text.split('BOOL pt_spawn(', 1)[1].split('BOOL pt_finish(', 1)[0]
    start = spawn.index('    handles[0] = CreateFileW(')
    stop = spawn.index('    if (!DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_OUTPUT_HANDLE)')
    fragment = spawn[start:stop]
    return (r'''
typedef BOOL (WINAPI *PT_COMPARE_OBJECT_HANDLES)(HANDLE, HANDLE);
typedef struct { HANDLE held; HMODULE comparison_module; PT_COMPARE_OBJECT_HANDLES compare; } PT_STDIN;
BOOL pt_stdin_select(PSID app_sid, const PT_STDIN *input, HANDLE *out) {
    HANDLE handles[3] = {NULL, NULL, NULL};
    SECURITY_ATTRIBUTES security = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    BOOL ok = FALSE;
    (void)app_sid; (void)input;
''' + fragment + r'''
    *out = handles[0]; ok = TRUE;
done:
    return ok;
}
''', False)


@pytest.fixture(scope='module')
def scripted_stdin(tmp_path_factory):
    text = (NATIVE / 'common.h').read_text(encoding='utf-8')
    block, complete = _tested_block(text)
    stages = sorted(set(re.findall(r'\bPT_DG_[A-Z_]+\b', text)))
    declarations = '\n'.join(f'#define {name} {index}' for index, name in enumerate(stages))
    compiler = shutil.which('cc')
    if compiler is None:
        pytest.skip('portable C compiler unavailable; no Windows qualification')
    directory = tmp_path_factory.mktemp('native-stdin-scripted')
    source, binary = directory / 'stdin-handoff.c', directory / 'stdin-handoff-check'
    source.write_text(f'#define PT_HAS_STDIN {int(complete)}\n' + declarations + '\n'
                      + PRELUDE + block + DRIVER, encoding='utf-8', newline='\n')
    env = {'PATH': os.defpath, 'LANG': 'C', 'LC_ALL': 'C'}
    built = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', str(source),
                            '-o', str(binary)], capture_output=True, timeout=20, env=env, check=False)
    assert built.returncode == 0, built.stderr.decode('utf-8', errors='replace')[:6000]

    def run(mode):
        result = subprocess.run([str(binary), mode], capture_output=True, timeout=5, env=env, check=False)
        assert result.returncode == 0, result.stderr.decode('utf-8', errors='replace')[:2000]
        assert not result.stderr and len(result.stdout) < 8192
        row = json.loads(result.stdout)
        assert not row.get('missing_helpers'), 'native stdin lease implementation is absent'
        assert row['bad_arguments'] == row['borrowed_close'] == row['stale_close'] == 0
        return row

    return run


def test_actual_selector_forwards_held_input_without_reopening_nul(scripted_stdin):
    row = scripted_stdin('select-forward')
    assert row['result'] == 1 and row['nul'] == 0 and row['duplicates'] == 1
    assert row['output_flags'] == row['output_object'] == 1


def test_fresh_parent_still_creates_readonly_nul(scripted_stdin):
    row = scripted_stdin('select-fresh')
    assert row['result'] == 1 and row['nul'] == 1 and row['duplicates'] == 0
    assert row['output_flags'] == row['output_object'] == 1


def test_fresh_parent_keeps_actual_nul_failure(scripted_stdin):
    row = scripted_stdin('select-nul-fails')
    assert row['result'] == 0 and row['error'] == 5 and row['output'] == 0


@pytest.mark.parametrize('mode', ['select-neither', 'select-both'])
def test_selection_modes_are_explicit_and_do_not_open_on_invalid_mix(scripted_stdin, mode):
    row = scripted_stdin(mode)
    assert row['result'] == 0 and row['error'] == 13
    assert row['nul'] == row['duplicates'] == row['output'] == 0


@pytest.mark.parametrize('mode', ['select-fresh-pipe', 'select-fresh-protected', 'select-cleanup-error'])
def test_fresh_reference_validation_and_cleanup_preserve_primary(scripted_stdin, mode):
    row = scripted_stdin(mode)
    assert row['result'] == 0 and row['error'] == 13 and row['output'] == 0
    assert row['closes'] == 1


@pytest.mark.parametrize('mode,error', [
    ('capture-load-fails', 701), ('capture-export-fails', 702), ('capture-export-cleanup-fails', 702),
    ('capture-no-flag', 13), ('capture-current-null', 13), ('capture-current-invalid', 13),
    ('capture-startup-null', 13), ('capture-startup-invalid', 13), ('capture-pipe', 13),
    ('capture-disk', 13), ('capture-unknown', 13), ('capture-type-error', 705),
    ('capture-identity', 13), ('capture-duplicate-fails', 601), ('capture-private-flags', 13),
    ('capture-private-type', 13), ('capture-private-identity', 13), ('capture-race', 13),
    ('capture-query-fails', 706), ('capture-validation-cleanup-fails', 13),
])
def test_capture_refuses_uncertain_input_and_keeps_first_error(scripted_stdin, mode, error):
    row = scripted_stdin(mode)
    assert row['result'] == 0 and row['error'] == error and row['empty'] == 1
    assert row['nul'] == 0 and row['output'] == 0 and row['frees'] <= 1 and row['closes'] <= 1


def test_capture_accepts_distinct_handles_for_same_object_and_owns_only_its_copy(scripted_stdin):
    row = scripted_stdin('capture-ok')
    assert row['result'] == row['held_object'] == row['release'] == row['second_release'] == row['empty'] == 1
    assert row['held_flags'] == row['nul'] == 0
    assert row['duplicates'] == row['closes'] == row['loads'] == row['exports'] == row['frees'] == 1
    assert row['release_error'] == 345


def test_forward_uses_an_inheritable_same_object_duplicate(scripted_stdin):
    row = scripted_stdin('forward-ok')
    assert row['result'] == row['output_object'] == row['output_flags'] == row['release'] == 1
    assert row['nul'] == row['held_flags'] == 0 and row['duplicates'] == row['closes'] == 2


@pytest.mark.parametrize('mode,error', [
    ('forward-replaced', 13), ('forward-duplicate-fails', 602), ('forward-private-inherit', 13),
    ('forward-private-protected', 13), ('forward-copy-flags', 13), ('forward-copy-protected', 13),
    ('forward-copy-type', 13), ('forward-copy-identity', 13), ('forward-cleanup-fails', 13),
    ('forward-race', 13),
])
def test_forward_refuses_changed_identity_flags_or_copy_and_preserves_primary(scripted_stdin, mode, error):
    row = scripted_stdin(mode)
    assert row['result'] == 0 and row['error'] == error and row['output'] == row['nul'] == 0
    assert row['empty'] == 1 and row['frees'] == 1


def test_forward_does_not_overwrite_or_close_existing_output_owner(scripted_stdin):
    row = scripted_stdin('forward-occupied')
    assert row['result'] == 0 and row['error'] == 13 and row['output'] == 30 and row['external_open'] == 1
    assert row['duplicates'] == row['closes'] == 1


@pytest.mark.parametrize('mode,error', [
    ('release-close-fails', 708), ('release-module-fails', 709), ('release-both-fail', 708),
])
def test_release_attempts_both_owned_closes_once_and_reports_first_failure(scripted_stdin, mode, error):
    row = scripted_stdin(mode)
    assert row['release'] == 0 and row['release_error'] == error
    assert row['closes'] == row['frees'] == row['empty'] == row['second_release'] == 1


def test_successful_release_cannot_retry_a_stale_handle(scripted_stdin):
    row = scripted_stdin('release-twice')
    assert row['release'] == row['second_release'] == row['closes'] == row['frees'] == 1


def test_static_runtime_binding_is_exact_and_does_not_change_borrowed_flags():
    text = (NATIVE / 'common.h').read_text(encoding='utf-8')
    assert BEGIN in text, 'stdin implementation boundary is absent'
    block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    assert 'BOOL (WINAPI *PT_COMPARE_OBJECT_HANDLES)(HANDLE, HANDLE)' in block
    assert 'LoadLibraryExW(L"kernelbase.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)' in block
    assert 'GetProcAddress(input->comparison_module, "CompareObjectHandles")' in block
    assert '(PT_COMPARE_OBJECT_HANDLES)' in block
    assert all(name not in block for name in ('GetModuleHandle', 'SetHandleInformation', 'DUPLICATE_CLOSE_SOURCE'))


def test_static_spawn_releases_owned_stdin_before_success_and_keeps_containment():
    text = (NATIVE / 'common.h').read_text(encoding='utf-8')
    spawn = text.split('BOOL pt_spawn(', 1)[1].split('BOOL pt_finish(', 1)[0]
    assert 'const PT_STDIN *inherited_input' in spawn
    assert 'pt_stdin_select(app_sid, inherited_input, &handles[0])' in spawn
    assert 'CreateFileW(L"NUL"' not in spawn
    assert spawn.index('AssignProcessToJobObject') < spawn.index('stdin_owned = FALSE; /* consumed */')
    assert spawn.index('stdin_owned = FALSE; /* consumed */') < spawn.index('CloseHandle(handles[0])') < spawn.index('ok = TRUE;')
    assert '(i != 0 || stdin_owned)' in spawn
    assert 'CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW |' in spawn
    assert 'PROC_THREAD_ATTRIBUTE_HANDLE_LIST' in spawn and 'handles, sizeof(handles)' in spawn
    assert 'caps.CapabilityCount = 0;' in spawn and 'wcscmp(child->identity.sid, wanted)' in spawn
    assert 'wcscmp(child->identity.sid, expected.sid)' in spawn


def test_static_probe_holds_lease_through_body_and_keeps_failure_primary():
    text = (NATIVE / 'probe.c').read_text(encoding='utf-8')
    assert 'pt_spawn(10, child_args, NULL, input, &child)' in text
    wrapper = text.split('int wmain(', 1)[1]
    assert wrapper.index('pt_stdin_capture(') < wrapper.index('pt_probe_main(') < wrapper.index('pt_stdin_release(')
    assert wrapper.index('primary = GetLastError();') < wrapper.index('pt_stdin_release(')
    assert 'if (code) SetLastError(primary);' in wrapper
    launcher = (NATIVE / 'launcher.c').read_text(encoding='utf-8')
    assert 'pt_spawn(argc - 6, argv + 6, sid, NULL, &child)' in launcher
