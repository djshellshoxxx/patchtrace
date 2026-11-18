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
    return WriteFile(file, text, size, &written, NULL) && written == size && FlushFileBuffers(file);
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
    DWORD timeout, code = 125;
    BOOL expired = FALSE, empty;
    char record[4096];
    if (argc >= 2 && (wcscmp(argv[1], L"profile-create") == 0 ||
                      wcscmp(argv[1], L"profile-delete") == 0)) return profile(argc, argv);
    if (argc >= 3 && wcscmp(argv[1], L"alive") == 0) return alive(argc, argv);
    if (argc < 7 || wcscmp(argv[1], L"launch") != 0 || wcscmp(argv[5], L"--") != 0) return 125;
    timeout = wcstoul(argv[4], &end, 10);
    if (*end || timeout < 1 || timeout > 120000 || !ConvertStringSidToSidW(argv[2], &sid)) return 125;
    receipt = CreateFileW(argv[3], GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (receipt == INVALID_HANDLE_VALUE) { LocalFree(sid); return 125; }
    if (!pt_spawn(argc - 6, argv + 6, sid, &child)) {
        snprintf(record, sizeof(record), "{\"phase\":\"refused\",\"error\":%lu}\n", GetLastError());
        write_record(receipt, record);
        CloseHandle(receipt); LocalFree(sid); return 125;
    }
    LocalFree(sid);
    snprintf(record, sizeof(record),
             "{\"phase\":\"started\",\"owner_pid\":%lu,\"pid\":%lu,\"created\":\"%llu\",\"sid\":\"%ls\","
             "\"appcontainer\":true,\"capability_count\":%lu,\"suspended\":true,"
             "\"job_before_resume\":true,\"token_before_resume\":true,\"image_locked\":true,"
             "\"handles\":[\"nul\",\"pipe\",\"pipe\"]}\n",
             GetCurrentProcessId(), child.identity.pid, child.identity.created, child.identity.sid,
             child.identity.capabilities);
    if (!write_record(receipt, record) || ResumeThread(child.process.hThread) == (DWORD)-1) {
        TerminateJobObject(child.job, 125);
        pt_finish(&child, 5000, &code, &expired);
        CloseHandle(receipt);
        return 125;
    }
    empty = pt_finish(&child, timeout, &code, &expired);
    snprintf(record, sizeof(record), "{\"phase\":\"finished\",\"tree_empty\":%s,"
             "\"returncode\":%lu,\"timed_out\":%s}\n", empty ? "true" : "false", code,
             expired ? "true" : "false");
    if (!write_record(receipt, record)) empty = FALSE;
    CloseHandle(receipt);
    return empty ? (int)code : 125;
}
