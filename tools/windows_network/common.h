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

/* PT_DIAGNOSTIC_PORTABLE_BEGIN */
/* One serial helper process, fixed vocabulary, no input strings or stdout.
   The final slot reports truncation. Failed writes also consume their slot. */
#define PT_DIAG_STAGES(X) \
    X(UNKNOWN, "unknown") X(DIAGNOSTIC_LIMIT, "diagnostic-limit") \
    X(PROCESS_ID, "process-id") X(PROCESS_TIMES, "process-times") \
    X(PROCESS_TOKEN, "process-token") X(TOKEN_APPCONTAINER, "token-appcontainer") \
    X(TOKEN_CAPABILITIES, "token-capabilities") X(TOKEN_SID, "token-sid") \
    X(CAPABILITY_COUNT, "capability-count") X(APP_SID, "app-sid") \
    X(SID_TEXT, "sid-text") X(SID_BOUND, "sid-bound") \
    X(PROCESS_SNAPSHOT, "process-snapshot") X(PROCESS_PARENT, "process-parent") \
    X(ARGUMENT_BOUND, "argument-bound") X(COMMAND_BUFFER, "command-buffer") \
    X(COMMAND_FORMAT, "command-format") X(IMAGE_OPEN, "image-open") \
    X(STDIO_KIND, "stdio-kind") X(NUL_OPEN, "nul-open") \
    X(STDOUT_DUPLICATE, "stdout-duplicate") X(STDERR_DUPLICATE, "stderr-duplicate") \
    X(ATTRIBUTE_SIZE, "attribute-size") X(ATTRIBUTE_BUFFER, "attribute-buffer") \
    X(ATTRIBUTE_INITIALIZE, "attribute-initialize") X(ATTRIBUTE_HANDLES, "attribute-handles") \
    X(ATTRIBUTE_CAPABILITIES, "attribute-capabilities") X(PARENT_TOKEN, "parent-token") \
    X(JOB_CREATE, "job-create") X(JOB_LIMITS, "job-limits") \
    X(PROCESS_CREATE, "process-create") X(JOB_ASSIGN, "job-assign") \
    X(CHILD_TOKEN, "child-token") X(TOKEN_MATCH, "token-match") \
    X(STARTUP_TERMINATE, "startup-terminate") X(STARTUP_WAIT, "startup-wait") \
    X(HANDLE_CLOSE, "handle-close") X(PROCESS_WAIT, "process-wait") \
    X(FINISH_WAIT, "finish-wait") X(EXIT_CODE, "exit-code") \
    X(JOB_TERMINATE, "job-terminate") X(JOB_QUERY, "job-query") X(JOB_EMPTY, "job-empty") \
    X(CHILD_EXIT, "child-exit") X(CHILD_SPAWN, "child-spawn") \
    X(CHILD_RESUME, "child-resume") X(CHILD_FINISH, "child-finish") \
    X(PROBE_ARGUMENTS, "probe-arguments") X(WINSOCK_STARTUP, "winsock-startup") \
    X(WINSOCK_CLEANUP, "winsock-cleanup") \
    X(RECEIPT_OPEN, "receipt-open") X(RECEIPT_WRITE, "receipt-write") X(RECEIPT_FLUSH, "receipt-flush") \
    X(SOCKET_ADDRESS, "socket-address") X(SOCKET_CREATE, "socket-create") \
    X(SOCKET_NONBLOCK, "socket-nonblock") X(SOCKET_CONNECT, "socket-connect") \
    X(SOCKET_CONNECT_WAIT, "socket-connect-wait") X(SOCKET_ERROR, "socket-error") \
    X(SOCKET_SEND, "socket-send") X(SOCKET_SEND_WAIT, "socket-send-wait") \
    X(SOCKET_RECEIVE, "socket-receive") X(SOCKET_RECEIVE_WAIT, "socket-receive-wait") \
    X(SOCKET_ECHO, "socket-echo") X(SOCKET_CLOSE, "socket-close")
#define PT_DIAG_KINDS(X) \
    X(UNKNOWN, "unknown") X(WIN32, "win32") X(WINSOCK, "winsock") X(VALIDATION, "validation") \
    X(TIMEOUT, "timeout") X(CHILD_EXIT, "child-exit") X(WAIT_RESULT, "wait-result") X(TRUNCATED, "truncated")
#define PT_DIAG_STAGE_ENUM(name, text) PT_DG_##name,
typedef enum { PT_DIAG_STAGES(PT_DIAG_STAGE_ENUM) PT_DG_COUNT } PT_DIAG_STAGE;
#undef PT_DIAG_STAGE_ENUM
#define PT_DIAG_KIND_ENUM(name, text) PT_DK_##name,
typedef enum { PT_DIAG_KINDS(PT_DIAG_KIND_ENUM) PT_DK_COUNT } PT_DIAG_KIND;
#undef PT_DIAG_KIND_ENUM
static uint32_t pt_diag_count = 0;

void pt_diag_emit(PT_DIAG_STAGE stage, PT_DIAG_KIND kind, uint32_t owner, uint32_t subject,
                  uint32_t error, uint32_t socket_index, uint32_t sent, uint32_t received) {
#define PT_DIAG_TEXT(name, text) text,
    static const char *const stages[] = {PT_DIAG_STAGES(PT_DIAG_TEXT)};
    static const char *const kinds[] = {PT_DIAG_KINDS(PT_DIAG_TEXT)};
#undef PT_DIAG_TEXT
    char record[512];
    int length;
    if (pt_diag_count >= 16) return;
    ++pt_diag_count;
    if (pt_diag_count == 16) {
        stage = PT_DG_DIAGNOSTIC_LIMIT; kind = PT_DK_TRUNCATED;
        subject = error = sent = received = 0; socket_index = UINT32_MAX;
    }
    if ((unsigned int)stage >= PT_DG_COUNT) stage = PT_DG_UNKNOWN;
    if ((unsigned int)kind >= PT_DK_COUNT) kind = PT_DK_UNKNOWN;
    length = snprintf(record, sizeof(record),
        "{\"diagnostic\":\"windows-network-diagnostic/1\",\"sequence\":%lu,\"stage\":\"%s\",\"kind\":\"%s\","
        "\"owner_pid\":%lu,\"subject_pid\":%lu,\"error\":%lu,\"socket_index\":%lu,"
        "\"sent_bytes\":%lu,\"received_bytes\":%lu}\n",
        (unsigned long)pt_diag_count, stages[stage], kinds[kind], (unsigned long)owner,
        (unsigned long)subject, (unsigned long)error, (unsigned long)socket_index,
        (unsigned long)sent, (unsigned long)received);
    if (length > 0 && (size_t)length < sizeof(record)) {
        (void)fwrite(record, 1, (size_t)length, stderr);
        (void)fflush(stderr);
    }
}
#undef PT_DIAG_STAGES
#undef PT_DIAG_KINDS
/* PT_DIAGNOSTIC_PORTABLE_END */

void pt_diag_win32(PT_DIAG_STAGE stage, DWORD subject) {
    DWORD error = GetLastError();
    pt_diag_emit(stage, PT_DK_WIN32, GetCurrentProcessId(), subject, error, UINT32_MAX, 0, 0);
    SetLastError(error);
}

void pt_diag_value(PT_DIAG_STAGE stage, PT_DIAG_KIND kind, DWORD subject, DWORD error) {
    DWORD saved = GetLastError();
    pt_diag_emit(stage, kind, GetCurrentProcessId(), subject, error, UINT32_MAX, 0, 0);
    SetLastError(saved);
}

void pt_diag_validation(PT_DIAG_STAGE stage, DWORD subject) {
    pt_diag_value(stage, PT_DK_VALIDATION, subject, 0);
}

void pt_diag_wait(PT_DIAG_STAGE stage, DWORD subject, DWORD result) {
    if (result == WAIT_FAILED) pt_diag_win32(stage, subject);
    else pt_diag_value(stage, result == WAIT_TIMEOUT ? PT_DK_TIMEOUT : PT_DK_WAIT_RESULT, subject, result);
}

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
    if (!out->pid) { pt_diag_win32(PT_DG_PROCESS_ID, 0); return FALSE; }
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        pt_diag_win32(PT_DG_PROCESS_TIMES, out->pid); return FALSE;
    }
    out->created = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        pt_diag_win32(PT_DG_PROCESS_TOKEN, out->pid); return FALSE;
    }
    if (!GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value), &needed)) {
        pt_diag_win32(PT_DG_TOKEN_APPCONTAINER, out->pid); goto done;
    }
    out->appcontainer = value != 0;
    if (!GetTokenInformation(token, TokenCapabilities, storage.bytes, sizeof(storage.bytes), &needed)) {
        pt_diag_win32(PT_DG_TOKEN_CAPABILITIES, out->pid); goto done;
    }
    groups = (PTOKEN_GROUPS)storage.bytes;
    out->capabilities = groups->GroupCount;
    if (out->capabilities > 1024) { pt_diag_validation(PT_DG_CAPABILITY_COUNT, out->pid); goto done; }
    if (out->appcontainer) {
        if (!GetTokenInformation(token, TokenAppContainerSid, storage.bytes, sizeof(storage.bytes), &needed)) {
            pt_diag_win32(PT_DG_TOKEN_SID, out->pid); goto done;
        }
        app = (PTOKEN_APPCONTAINER_INFORMATION)storage.bytes;
        if (!app->TokenAppContainer) { pt_diag_validation(PT_DG_APP_SID, out->pid); goto done; }
        if (!ConvertSidToStringSidW(app->TokenAppContainer, &text)) {
            pt_diag_win32(PT_DG_SID_TEXT, out->pid); goto done;
        }
        if (wcslen(text) >= 256 || wcscpy_s(out->sid, 256, text) != 0) {
            pt_diag_validation(PT_DG_SID_BOUND, out->pid); goto done;
        }
    }
    ok = TRUE;
done:
    if (text) LocalFree(text);
    if (!CloseHandle(token)) pt_diag_win32(PT_DG_HANDLE_CLOSE, out->pid);
    return ok;
}

DWORD pt_parent(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W row;
    DWORD parent = 0, count = 0;
    if (snapshot == INVALID_HANDLE_VALUE) { pt_diag_win32(PT_DG_PROCESS_SNAPSHOT, pid); return 0; }
    ZeroMemory(&row, sizeof(row));
    row.dwSize = sizeof(row);
    if (Process32FirstW(snapshot, &row)) {
        do {
            if (++count > 32768) break;
            if (row.th32ProcessID == pid) { parent = row.th32ParentProcessID; break; }
        } while (Process32NextW(snapshot, &row));
    } else pt_diag_win32(PT_DG_PROCESS_SNAPSHOT, pid);
    if (!CloseHandle(snapshot)) pt_diag_win32(PT_DG_HANDLE_CLOSE, pid);
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
    if (count < 1 || count > 64) { pt_diag_validation(PT_DG_ARGUMENT_BOUND, 0); goto done; }
    command = (wchar_t *)calloc(32768, sizeof(wchar_t));
    if (!command) { pt_diag_validation(PT_DG_COMMAND_BUFFER, 0); goto done; }
    if (!pt_command(count, args, command)) { pt_diag_validation(PT_DG_COMMAND_FORMAT, 0); goto done; }
    /* Keep the image open without write/delete sharing for its complete run. */
    child->image = CreateFileW(args[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (child->image == INVALID_HANDLE_VALUE) {
        pt_diag_win32(PT_DG_IMAGE_OPEN, 0); child->image = NULL; goto done;
    }
    if (GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) != FILE_TYPE_PIPE ||
        GetFileType(GetStdHandle(STD_ERROR_HANDLE)) != FILE_TYPE_PIPE) {
        pt_diag_validation(PT_DG_STDIO_KIND, 0); goto done;
    }
    handles[0] = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handles[0] == INVALID_HANDLE_VALUE) {
        pt_diag_win32(PT_DG_NUL_OPEN, 0); handles[0] = NULL; goto done;
    }
    if (!DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_OUTPUT_HANDLE), GetCurrentProcess(),
                         &handles[1], 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        pt_diag_win32(PT_DG_STDOUT_DUPLICATE, 0); goto done;
    }
    if (!DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_ERROR_HANDLE), GetCurrentProcess(),
                         &handles[2], 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        pt_diag_win32(PT_DG_STDERR_DUPLICATE, 0); goto done;
    }
    InitializeProcThreadAttributeList(NULL, app_sid ? 2 : 1, 0, &size);
    if (!size || size > 65536) { pt_diag_validation(PT_DG_ATTRIBUTE_SIZE, 0); goto done; }
    startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(size);
    if (!startup.lpAttributeList) { pt_diag_validation(PT_DG_ATTRIBUTE_BUFFER, 0); goto done; }
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, app_sid ? 2 : 1, 0, &size)) {
        pt_diag_win32(PT_DG_ATTRIBUTE_INITIALIZE, 0); goto done;
    }
    attributes_ready = TRUE;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   handles, sizeof(handles), NULL, NULL)) {
        pt_diag_win32(PT_DG_ATTRIBUTE_HANDLES, 0); goto done;
    }
    if (app_sid) {
        caps.AppContainerSid = app_sid;
        caps.Capabilities = NULL;
        caps.CapabilityCount = 0;
        if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0,
                                       PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                       &caps, sizeof(caps), NULL, NULL)) {
            pt_diag_win32(PT_DG_ATTRIBUTE_CAPABILITIES, 0); goto done;
        }
        if (!ConvertSidToStringSidW(app_sid, &wanted)) { pt_diag_win32(PT_DG_SID_TEXT, 0); goto done; }
    } else if (!pt_identity(GetCurrentProcess(), &expected)) {
        pt_diag_validation(PT_DG_PARENT_TOKEN, 0); goto done;
    }
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    child->job = CreateJobObjectW(NULL, NULL);
    if (!child->job) { pt_diag_win32(PT_DG_JOB_CREATE, 0); goto done; }
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                             JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if (!SetInformationJobObject(child->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        pt_diag_win32(PT_DG_JOB_LIMITS, 0); goto done;
    }
    if (!CreateProcessW(args[0], command, NULL, NULL, TRUE,
                         CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW |
                         EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                         &startup.StartupInfo, &child->process)) {
        pt_diag_win32(PT_DG_PROCESS_CREATE, 0); goto done;
    }
    if (!AssignProcessToJobObject(child->job, child->process.hProcess)) {
        pt_diag_win32(PT_DG_JOB_ASSIGN, child->process.dwProcessId); goto done;
    }
    if (!pt_identity(child->process.hProcess, &child->identity)) {
        pt_diag_validation(PT_DG_CHILD_TOKEN, child->process.dwProcessId); goto done;
    }
    if (app_sid) {
        if (!child->identity.appcontainer || child->identity.capabilities != 0 ||
            wcscmp(child->identity.sid, wanted) != 0) {
            pt_diag_validation(PT_DG_TOKEN_MATCH, child->identity.pid); goto done;
        }
    } else {
        if (child->identity.appcontainer != expected.appcontainer ||
            child->identity.capabilities != expected.capabilities ||
            wcscmp(child->identity.sid, expected.sid) != 0) {
            pt_diag_validation(PT_DG_TOKEN_MATCH, child->identity.pid); goto done;
        }
    }
    ok = TRUE;
done:
    if (!ok) {
        saved = GetLastError();
        if (!saved) saved = ERROR_INVALID_DATA;
        if (child->process.hProcess) {
            DWORD waited;
            if (!TerminateProcess(child->process.hProcess, 125))
                pt_diag_win32(PT_DG_STARTUP_TERMINATE, child->process.dwProcessId);
            waited = WaitForSingleObject(child->process.hProcess, 5000);
            if (waited != WAIT_OBJECT_0) pt_diag_wait(PT_DG_STARTUP_WAIT, child->process.dwProcessId, waited);
            if (!CloseHandle(child->process.hProcess)) pt_diag_win32(PT_DG_HANDLE_CLOSE, child->process.dwProcessId);
            if (!CloseHandle(child->process.hThread)) pt_diag_win32(PT_DG_HANDLE_CLOSE, child->process.dwProcessId);
        }
        if (child->job && !CloseHandle(child->job)) pt_diag_win32(PT_DG_HANDLE_CLOSE, child->process.dwProcessId);
        if (child->image && !CloseHandle(child->image)) pt_diag_win32(PT_DG_HANDLE_CLOSE, child->process.dwProcessId);
        ZeroMemory(child, sizeof(*child));
    }
    if (startup.lpAttributeList) {
        if (attributes_ready) DeleteProcThreadAttributeList(startup.lpAttributeList);
        free(startup.lpAttributeList);
    }
    for (i = 0; i < 3; ++i)
        if (handles[i] && !CloseHandle(handles[i])) pt_diag_win32(PT_DG_HANDLE_CLOSE, child->process.dwProcessId);
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
    if (wait != WAIT_OBJECT_0) {
        pt_diag_wait(PT_DG_PROCESS_WAIT, child->process.dwProcessId, wait);
        if (!TerminateJobObject(child->job, 124)) pt_diag_win32(PT_DG_JOB_TERMINATE, child->process.dwProcessId);
    }
    wait = WaitForSingleObject(child->process.hProcess, 5000);
    if (wait != WAIT_OBJECT_0) pt_diag_wait(PT_DG_FINISH_WAIT, child->process.dwProcessId, wait);
    if (!GetExitCodeProcess(child->process.hProcess, code)) {
        pt_diag_win32(PT_DG_EXIT_CODE, child->process.dwProcessId); *code = 125;
    } else if (*code) pt_diag_value(PT_DG_CHILD_EXIT, PT_DK_CHILD_EXIT, child->process.dwProcessId, *code);
    /* Even a normally exiting immediate child may leave descendants. */
    if (!TerminateJobObject(child->job, 124)) pt_diag_win32(PT_DG_JOB_TERMINATE, child->process.dwProcessId);
    deadline = GetTickCount64() + 10000;
    do {
        ZeroMemory(&info, sizeof(info));
        if (!QueryInformationJobObject(child->job, JobObjectBasicAccountingInformation,
                                        &info, sizeof(info), NULL)) {
            pt_diag_win32(PT_DG_JOB_QUERY, child->process.dwProcessId); break;
        }
        if (!info.ActiveProcesses) { empty = TRUE; break; }
        Sleep(10);
    } while (GetTickCount64() < deadline);
    if (!empty) pt_diag_validation(PT_DG_JOB_EMPTY, child->process.dwProcessId);
    if (!CloseHandle(child->process.hThread)) pt_diag_win32(PT_DG_HANDLE_CLOSE, child->process.dwProcessId);
    if (!CloseHandle(child->process.hProcess)) pt_diag_win32(PT_DG_HANDLE_CLOSE, child->process.dwProcessId);
    if (!CloseHandle(child->job)) pt_diag_win32(PT_DG_HANDLE_CLOSE, child->process.dwProcessId);
    if (!CloseHandle(child->image)) pt_diag_win32(PT_DG_HANDLE_CLOSE, child->process.dwProcessId);
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
