/* Authored acceptance tooling. Windows SDK only; no third-party native code. */
#ifndef PATCHTRACE_NETWORK_COMMON_H
#define PATCHTRACE_NETWORK_COMMON_H
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <userenv.h>
#include <objbase.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <wchar.h>

typedef struct {
    DWORD pid, parent, capabilities;
    BOOL appcontainer;
    ULONGLONG created;
    wchar_t sid[256];
} PT_IDENTITY;

typedef struct {
    PROCESS_INFORMATION process;
    HANDLE job, image;
    PT_IDENTITY identity;
} PT_CHILD;

BOOL pt_identity(HANDLE process, PT_IDENTITY *out) {
    HANDLE token = NULL;
    DWORD needed = 0, value = 0;
    FILETIME created, exited, kernel, user;
    union { void *alignment; BYTE bytes[16384]; } storage;
    PTOKEN_APPCONTAINER_INFORMATION app;
    PTOKEN_GROUPS groups;
    LPWSTR text = NULL;
    BOOL ok = FALSE;
    ZeroMemory(out, sizeof(*out));
    out->pid = GetProcessId(process);
    if (!out->pid || !GetProcessTimes(process, &created, &exited, &kernel, &user)) return FALSE;
    out->created = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return FALSE;
    if (!GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value), &needed)) goto done;
    out->appcontainer = value != 0;
    if (!GetTokenInformation(token, TokenCapabilities, storage.bytes, sizeof(storage.bytes), &needed)) goto done;
    groups = (PTOKEN_GROUPS)storage.bytes;
    out->capabilities = groups->GroupCount;
    if (out->capabilities > 1024) goto done;
    if (out->appcontainer) {
        if (!GetTokenInformation(token, TokenAppContainerSid, storage.bytes, sizeof(storage.bytes), &needed)) goto done;
        app = (PTOKEN_APPCONTAINER_INFORMATION)storage.bytes;
        if (!app->TokenAppContainer || !ConvertSidToStringSidW(app->TokenAppContainer, &text)) goto done;
        if (wcslen(text) >= 256 || wcscpy_s(out->sid, 256, text) != 0) goto done;
    }
    ok = TRUE;
done:
    if (text) LocalFree(text);
    CloseHandle(token);
    return ok;
}

DWORD pt_parent(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W row;
    DWORD parent = 0, count = 0;
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    ZeroMemory(&row, sizeof(row));
    row.dwSize = sizeof(row);
    if (Process32FirstW(snapshot, &row)) {
        do {
            if (++count > 32768) break;
            if (row.th32ProcessID == pid) { parent = row.th32ParentProcessID; break; }
        } while (Process32NextW(snapshot, &row));
    }
    CloseHandle(snapshot);
    return parent;
}

BOOL pt_push(wchar_t *out, size_t *used, wchar_t ch) {
    if (*used >= 32766) return FALSE;
    out[(*used)++] = ch;
    out[*used] = 0;
    return TRUE;
}

BOOL pt_command(int count, wchar_t **args, wchar_t *out) {
    size_t used = 0, slashes, i, j;
    int arg;
    out[0] = 0;
    for (arg = 0; arg < count; ++arg) {
        if (arg && !pt_push(out, &used, L' ')) return FALSE;
        if (!pt_push(out, &used, L'"')) return FALSE;
        slashes = 0;
        for (i = 0; args[arg][i]; ++i) {
            if (args[arg][i] == L'\\') { ++slashes; continue; }
            for (j = 0; j < slashes * (args[arg][i] == L'"' ? 2 : 1); ++j)
                if (!pt_push(out, &used, L'\\')) return FALSE;
            slashes = 0;
            if (args[arg][i] == L'"' && !pt_push(out, &used, L'\\')) return FALSE;
            if (!pt_push(out, &used, args[arg][i])) return FALSE;
        }
        for (j = 0; j < slashes * 2; ++j) if (!pt_push(out, &used, L'\\')) return FALSE;
        if (!pt_push(out, &used, L'"')) return FALSE;
    }
    return TRUE;
}

/* Returns a suspended, token-verified child in an owned non-breakaway job.
   Only three fresh stdio handles are inherited. Never resumes on failure. */
BOOL pt_spawn(int count, wchar_t **args, PSID app_sid, PT_CHILD *child) {
    STARTUPINFOEXW startup;
    SECURITY_ATTRIBUTES security = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    SECURITY_CAPABILITIES caps;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    PT_IDENTITY expected;
    HANDLE handles[3] = {NULL, NULL, NULL};
    SIZE_T size = 0;
    wchar_t *command = NULL, *wanted = NULL;
    BOOL ok = FALSE, attributes_ready = FALSE;
    DWORD saved = ERROR_INVALID_DATA;
    int i;
    ZeroMemory(child, sizeof(*child));
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&caps, sizeof(caps));
    ZeroMemory(&limits, sizeof(limits));
    ZeroMemory(&expected, sizeof(expected));
    if (count < 1 || count > 64) goto done;
    command = (wchar_t *)calloc(32768, sizeof(wchar_t));
    if (!command || !pt_command(count, args, command)) goto done;
    /* Keep the image open without write/delete sharing for its complete run. */
    child->image = CreateFileW(args[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (child->image == INVALID_HANDLE_VALUE) { child->image = NULL; goto done; }
    if (GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) != FILE_TYPE_PIPE ||
        GetFileType(GetStdHandle(STD_ERROR_HANDLE)) != FILE_TYPE_PIPE) goto done;
    handles[0] = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handles[0] == INVALID_HANDLE_VALUE) { handles[0] = NULL; goto done; }
    if (!DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_OUTPUT_HANDLE), GetCurrentProcess(),
                         &handles[1], 0, TRUE, DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_ERROR_HANDLE), GetCurrentProcess(),
                         &handles[2], 0, TRUE, DUPLICATE_SAME_ACCESS)) goto done;
    InitializeProcThreadAttributeList(NULL, app_sid ? 2 : 1, 0, &size);
    if (!size || size > 65536) goto done;
    startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(size);
    if (!startup.lpAttributeList ||
        !InitializeProcThreadAttributeList(startup.lpAttributeList, app_sid ? 2 : 1, 0, &size)) goto done;
    attributes_ready = TRUE;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   handles, sizeof(handles), NULL, NULL)) goto done;
    if (app_sid) {
        caps.AppContainerSid = app_sid;
        caps.Capabilities = NULL;
        caps.CapabilityCount = 0;
        if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0,
                                       PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                       &caps, sizeof(caps), NULL, NULL)) goto done;
        if (!ConvertSidToStringSidW(app_sid, &wanted)) goto done;
    } else if (!pt_identity(GetCurrentProcess(), &expected)) goto done;
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    child->job = CreateJobObjectW(NULL, NULL);
    if (!child->job) goto done;
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                             JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if (!SetInformationJobObject(child->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) goto done;
    if (!CreateProcessW(args[0], command, NULL, NULL, TRUE,
                         CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW |
                         EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                         &startup.StartupInfo, &child->process)) goto done;
    if (!AssignProcessToJobObject(child->job, child->process.hProcess) ||
        !pt_identity(child->process.hProcess, &child->identity)) goto done;
    if (app_sid) {
        if (!child->identity.appcontainer || child->identity.capabilities != 0 ||
            wcscmp(child->identity.sid, wanted) != 0) goto done;
    } else {
        if (child->identity.appcontainer != expected.appcontainer ||
            child->identity.capabilities != expected.capabilities ||
            wcscmp(child->identity.sid, expected.sid) != 0) goto done;
    }
    ok = TRUE;
done:
    if (!ok) {
        saved = GetLastError();
        if (!saved) saved = ERROR_INVALID_DATA;
        if (child->process.hProcess) {
            TerminateProcess(child->process.hProcess, 125);
            WaitForSingleObject(child->process.hProcess, 5000);
            CloseHandle(child->process.hProcess);
            CloseHandle(child->process.hThread);
        }
        if (child->job) CloseHandle(child->job);
        if (child->image) CloseHandle(child->image);
        ZeroMemory(child, sizeof(*child));
    }
    if (startup.lpAttributeList) {
        if (attributes_ready) DeleteProcThreadAttributeList(startup.lpAttributeList);
        free(startup.lpAttributeList);
    }
    for (i = 0; i < 3; ++i) if (handles[i]) CloseHandle(handles[i]);
    if (wanted) LocalFree(wanted);
    free(command);
    if (!ok) SetLastError(saved);
    return ok;
}

BOOL pt_finish(PT_CHILD *child, DWORD timeout, DWORD *code, BOOL *expired) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
    ULONGLONG deadline;
    BOOL empty = FALSE;
    DWORD wait = WaitForSingleObject(child->process.hProcess, timeout);
    *expired = wait == WAIT_TIMEOUT;
    if (wait != WAIT_OBJECT_0) TerminateJobObject(child->job, 124);
    WaitForSingleObject(child->process.hProcess, 5000);
    if (!GetExitCodeProcess(child->process.hProcess, code)) *code = 125;
    /* Even a normally exiting immediate child may leave descendants. */
    TerminateJobObject(child->job, 124);
    deadline = GetTickCount64() + 10000;
    do {
        ZeroMemory(&info, sizeof(info));
        if (!QueryInformationJobObject(child->job, JobObjectBasicAccountingInformation,
                                        &info, sizeof(info), NULL)) break;
        if (!info.ActiveProcesses) { empty = TRUE; break; }
        Sleep(10);
    } while (GetTickCount64() < deadline);
    CloseHandle(child->process.hThread);
    CloseHandle(child->process.hProcess);
    CloseHandle(child->job);
    CloseHandle(child->image);
    ZeroMemory(child, sizeof(*child));
    return empty;
}

void pt_json_wide(const wchar_t *value) {
    char text[32768];
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, text, sizeof(text), NULL, NULL);
    int i;
    if (!n) { printf("null"); return; }
    putchar('"');
    for (i = 0; i < n - 1; ++i) {
        unsigned char ch = (unsigned char)text[i];
        if (ch == '"' || ch == '\\') { putchar('\\'); putchar(ch); }
        else if (ch < 32) printf("\\u%04x", (unsigned)ch);
        else putchar(ch);
    }
    putchar('"');
}
#endif
