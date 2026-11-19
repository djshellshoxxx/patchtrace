#include "common.h"

BOOL profile_name(const wchar_t *name) {
    const wchar_t *prefix = L"PatchTrace.Acceptance.";
    size_t i, length = wcslen(prefix);
    if (wcslen(name) != length + 32 || wcsncmp(name, prefix, length) != 0) return FALSE;
    for (i = length; i < length + 32; ++i)
        if (!((name[i] >= L'0' && name[i] <= L'9') || (name[i] >= L'a' && name[i] <= L'f'))) return FALSE;
    return TRUE;
}

int profile(int argc, wchar_t **argv) {
    HRESULT result;
    PSID sid = NULL;
    LPWSTR text = NULL, folder = NULL;
    if (argc != 3 || !profile_name(argv[2])) return 125;
    if (wcscmp(argv[1], L"profile-create") == 0) {
        result = CreateAppContainerProfile(argv[2], argv[2], L"Owned PatchTrace native acceptance", NULL, 0, &sid);
        if (FAILED(result)) { printf("{\"error\":%lu}\n", (DWORD)result); return 125; }
        if (!ConvertSidToStringSidW(sid, &text)) {
            DWORD error = GetLastError();
            HRESULT cleanup = DeleteAppContainerProfile(argv[2]);
            printf("{\"error\":%lu,\"created\":true,\"name\":", error);
            pt_json_wide(argv[2]);
            printf(",\"sid\":null,\"cleanup_hresult\":%lu}\n", (DWORD)cleanup);
            FreeSid(sid);
            return 125;
        }
        result = GetAppContainerFolderPath(text, &folder);
        printf("{\"created\":true,\"name\":"); pt_json_wide(argv[2]);
        printf(",\"sid\":"); pt_json_wide(text);
        printf(",\"capability_count\":0,\"folder\":");
        if (SUCCEEDED(result) && folder) pt_json_wide(folder); else printf("null");
        printf("}\n");
        if (folder) CoTaskMemFree(folder);
        LocalFree(text); FreeSid(sid);
        return 0;
    }
    result = DeleteAppContainerProfile(argv[2]);
    printf("{\"deleted\":%s,\"error\":%lu}\n", SUCCEEDED(result) ? "true" : "false", (DWORD)result);
    return SUCCEEDED(result) ? 0 : 125;
}

BOOL write_record(HANDLE file, const char *text) {
    DWORD written = 0, size = (DWORD)strlen(text);
    if (!WriteFile(file, text, size, &written, NULL)) { pt_diag_win32(PT_DG_RECEIPT_WRITE, 0); return FALSE; }
    if (written != size) { pt_diag_validation(PT_DG_RECEIPT_WRITE, 0); return FALSE; }
    if (!FlushFileBuffers(file)) { pt_diag_win32(PT_DG_RECEIPT_FLUSH, 0); return FALSE; }
    return TRUE;
}

int alive(int argc, wchar_t **argv) {
    int i, emitted = 0;
    BOOL uncertain = FALSE;
    printf("{\"alive\":[");
    for (i = 2; i < argc && i < 10; ++i) {
        wchar_t *colon = wcschr(argv[i], L':'), *end = NULL;
        DWORD pid;
        ULONGLONG expected;
        HANDLE process;
        FILETIME created, exited, kernel, user;
        if (!colon) { uncertain = TRUE; continue; }
        pid = wcstoul(argv[i], &end, 10);
        if (end != colon || !pid) { uncertain = TRUE; continue; }
        expected = _wcstoui64(colon + 1, &end, 10);
        if (*end || !expected) { uncertain = TRUE; continue; }
        process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) {
            if (GetLastError() != ERROR_INVALID_PARAMETER) uncertain = TRUE;
            continue;
        }
        if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) uncertain = TRUE;
        else if ((((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime) == expected &&
                  WaitForSingleObject(process, 0) != WAIT_OBJECT_0) {
            printf("%s%lu", emitted++ ? "," : "", pid);
        }
        CloseHandle(process);
    }
    printf("],\"uncertain\":%s}\n", uncertain || argc > 10 ? "true" : "false");
    return uncertain || argc > 10 ? 125 : 0;
}

int wmain(int argc, wchar_t **argv) {
    PSID sid = NULL;
    PT_CHILD child;
    HANDLE receipt = INVALID_HANDLE_VALUE;
    wchar_t *end = NULL;
    DWORD timeout, code = 125, child_pid;
    BOOL expired = FALSE, empty, recorded;
    char record[4096];
    if (argc >= 2 && (wcscmp(argv[1], L"profile-create") == 0 ||
                      wcscmp(argv[1], L"profile-delete") == 0)) return profile(argc, argv);
    if (argc >= 3 && wcscmp(argv[1], L"alive") == 0) return alive(argc, argv);
    if (argc < 7 || wcscmp(argv[1], L"launch") != 0 || wcscmp(argv[5], L"--") != 0) {
        pt_diag_validation(PT_DG_ARGUMENT_BOUND, 0); return 125;
    }
    timeout = wcstoul(argv[4], &end, 10);
    if (*end || timeout < 1 || timeout > 120000) { pt_diag_validation(PT_DG_ARGUMENT_BOUND, 0); return 125; }
    if (!ConvertStringSidToSidW(argv[2], &sid)) { pt_diag_win32(PT_DG_SID_TEXT, 0); return 125; }
    receipt = CreateFileW(argv[3], GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (receipt == INVALID_HANDLE_VALUE) { pt_diag_win32(PT_DG_RECEIPT_OPEN, 0); LocalFree(sid); return 125; }
    if (!pt_spawn(argc - 6, argv + 6, sid, NULL, &child)) {
        pt_diag_win32(PT_DG_CHILD_SPAWN, 0);
        snprintf(record, sizeof(record), "{\"phase\":\"refused\",\"error\":%lu}\n", GetLastError());
        write_record(receipt, record);
        if (!CloseHandle(receipt)) pt_diag_win32(PT_DG_HANDLE_CLOSE, 0);
        LocalFree(sid); return 125;
    }
    LocalFree(sid);
    child_pid = child.identity.pid;
    snprintf(record, sizeof(record),
             "{\"phase\":\"started\",\"owner_pid\":%lu,\"pid\":%lu,\"created\":\"%llu\",\"sid\":\"%ls\","
             "\"appcontainer\":true,\"capability_count\":%lu,\"suspended\":true,"
             "\"job_before_resume\":true,\"token_before_resume\":true,\"image_locked\":true,"
             "\"handles\":[\"nul\",\"pipe\",\"pipe\"]}\n",
             GetCurrentProcessId(), child.identity.pid, child.identity.created, child.identity.sid,
             child.identity.capabilities);
    recorded = write_record(receipt, record);
    if (!recorded || ResumeThread(child.process.hThread) == (DWORD)-1) {
        if (recorded) pt_diag_win32(PT_DG_CHILD_RESUME, child_pid);
        if (!TerminateJobObject(child.job, 125)) pt_diag_win32(PT_DG_JOB_TERMINATE, child_pid);
        pt_finish(&child, 5000, &code, &expired);
        if (!CloseHandle(receipt)) pt_diag_win32(PT_DG_HANDLE_CLOSE, 0);
        return 125;
    }
    empty = pt_finish(&child, timeout, &code, &expired);
    if (!empty || expired || code)
        pt_diag_value(PT_DG_CHILD_FINISH, expired ? PT_DK_TIMEOUT : code ? PT_DK_CHILD_EXIT : PT_DK_VALIDATION,
                      child_pid, code);
    snprintf(record, sizeof(record), "{\"phase\":\"finished\",\"tree_empty\":%s,"
             "\"returncode\":%lu,\"timed_out\":%s}\n", empty ? "true" : "false", code,
             expired ? "true" : "false");
    if (!write_record(receipt, record)) empty = FALSE;
    if (!CloseHandle(receipt)) pt_diag_win32(PT_DG_HANDLE_CLOSE, 0);
    return empty ? (int)code : 125;
}
