#include "common.h"

/* Only authored loopback echo listeners and this fixed public TCP endpoint.
   No DNS, HTTP request, target-file content or ambient proxy configuration. */
int wait_socket(SOCKET stream, BOOL writing, ULONGLONG deadline, PT_DIAG_KIND *kind) {
    fd_set ready, errors;
    struct timeval timeout;
    ULONGLONG now = GetTickCount64(), left;
    int result;
    *kind = PT_DK_WINSOCK;
    if (now >= deadline) { *kind = PT_DK_TIMEOUT; return WSAETIMEDOUT; }
    left = deadline - now;
    timeout.tv_sec = (long)(left / 1000);
    timeout.tv_usec = (long)((left % 1000) * 1000);
    FD_ZERO(&ready); FD_SET(stream, &ready);
    FD_ZERO(&errors); FD_SET(stream, &errors);
    result = select(0, writing ? NULL : &ready, writing ? &ready : NULL, &errors, &timeout);
    if (result == SOCKET_ERROR) return WSAGetLastError();
    if (!result) { *kind = PT_DK_TIMEOUT; return WSAETIMEDOUT; }
    return 0;
}

int socket_case(int family, BOOL udp, BOOL external, unsigned short port, const char *nonce) {
    SOCKET stream = INVALID_SOCKET;
    SOCKADDR_STORAGE storage;
    SOCKADDR_IN *v4 = (SOCKADDR_IN *)&storage;
    SOCKADDR_IN6 *v6 = (SOCKADDR_IN6 *)&storage;
    int size, error = 0, diagnostic_error = 0, length, result, sent = 0, received = 0;
    PT_DIAG_STAGE stage = PT_DG_SOCKET_ADDRESS;
    PT_DIAG_KIND kind = PT_DK_WINSOCK;
    uint32_t index = external ? 4 : udp ? (family == AF_INET6 ? 3 : 2) : (family == AF_INET6 ? 1 : 0);
    char echo[32];
    u_long nonblocking = 1;
    ULONGLONG deadline = GetTickCount64() + 4000;
    ZeroMemory(&storage, sizeof(storage));
    if (family == AF_INET) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(external ? 443 : port);
        result = InetPtonW(AF_INET, external ? L"1.1.1.1" : L"127.0.0.1", &v4->sin_addr);
        if (result != 1) {
            if (result == SOCKET_ERROR) diagnostic_error = WSAGetLastError();
            else kind = PT_DK_VALIDATION;
            error = WSAEINVAL; goto done; /* Preserve the original case return. */
        }
        size = sizeof(*v4);
    } else {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        result = InetPtonW(AF_INET6, L"::1", &v6->sin6_addr);
        if (result != 1) {
            if (result == SOCKET_ERROR) diagnostic_error = WSAGetLastError();
            else kind = PT_DK_VALIDATION;
            error = WSAEINVAL; goto done;
        }
        size = sizeof(*v6);
    }
    stage = PT_DG_SOCKET_CREATE;
    stream = socket(family, udp ? SOCK_DGRAM : SOCK_STREAM, udp ? IPPROTO_UDP : IPPROTO_TCP);
    if (stream == INVALID_SOCKET) { error = WSAGetLastError(); goto done; }
    stage = PT_DG_SOCKET_NONBLOCK;
    if (ioctlsocket(stream, FIONBIO, &nonblocking) == SOCKET_ERROR) { error = WSAGetLastError(); goto done; }
    stage = PT_DG_SOCKET_CONNECT;
    if (connect(stream, (SOCKADDR *)&storage, size) == SOCKET_ERROR) {
        error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS) goto done;
        stage = PT_DG_SOCKET_CONNECT_WAIT;
        error = wait_socket(stream, TRUE, deadline, &kind);
        if (error) goto done;
        length = sizeof(error);
        stage = PT_DG_SOCKET_ERROR;
        if (getsockopt(stream, SOL_SOCKET, SO_ERROR, (char *)&error, &length) == SOCKET_ERROR)
            error = WSAGetLastError();
        if (error) goto done;
    }
    if (external) goto done;
    while (sent < 32) {
        stage = PT_DG_SOCKET_SEND; kind = PT_DK_WINSOCK;
        result = send(stream, nonce + sent, 32 - sent, 0);
        if (result == SOCKET_ERROR) {
            error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) goto done;
            stage = PT_DG_SOCKET_SEND_WAIT;
            error = wait_socket(stream, TRUE, deadline, &kind);
            if (error) goto done;
        } else if (result <= 0) { kind = PT_DK_VALIDATION; error = WSAECONNRESET; goto done; }
        else sent += result;
    }
    while (received < 32) {
        stage = PT_DG_SOCKET_RECEIVE; kind = PT_DK_WINSOCK;
        result = recv(stream, echo + received, 32 - received, 0);
        if (result == SOCKET_ERROR) {
            error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) goto done;
            stage = PT_DG_SOCKET_RECEIVE_WAIT;
            error = wait_socket(stream, FALSE, deadline, &kind);
            if (error) goto done;
        } else if (result <= 0) { kind = PT_DK_VALIDATION; error = WSAECONNRESET; goto done; }
        else received += result;
    }
    if (memcmp(echo, nonce, 32) != 0) {
        stage = PT_DG_SOCKET_ECHO; kind = PT_DK_VALIDATION; error = WSAEINVAL;
    }
done:
    if (error) {
        DWORD saved = GetLastError();
        pt_diag_emit(stage, kind, GetCurrentProcessId(), 0,
                     (uint32_t)(diagnostic_error ? diagnostic_error : error), index,
                     (uint32_t)sent, (uint32_t)received);
        SetLastError(saved);
    }
    if (stream != INVALID_SOCKET && closesocket(stream) == SOCKET_ERROR) {
        int close_error = WSAGetLastError();
        pt_diag_value(PT_DG_SOCKET_CLOSE, PT_DK_WINSOCK, 0, (DWORD)close_error);
    }
    return error;
}

int pt_probe_main(int argc, wchar_t **argv, const PT_STDIN *input) {
    static const char *names[] = {"tcp4-loopback", "tcp6-loopback", "udp4-loopback",
                                  "udp6-loopback", "tcp4-external"};
    WSADATA winsock;
    PT_IDENTITY identity;
    PT_CHILD child;
    wchar_t *end = NULL, *child_args[10], depth_text[2];
    unsigned long depth, ports[4];
    char nonce[33];
    BOOL lifetime, expired;
    DWORD code, child_pid;
    int i, error;
    if (argc != 10 || (wcscmp(argv[1], L"chain") != 0 && wcscmp(argv[1], L"lifetime") != 0)) {
        pt_diag_validation(PT_DG_PROBE_ARGUMENTS, 0); return 125;
    }
    lifetime = wcscmp(argv[1], L"lifetime") == 0;
    if (wcslen(argv[2]) != 32) { pt_diag_validation(PT_DG_PROBE_ARGUMENTS, 0); return 125; }
    for (i = 0; i < 32; ++i) {
        if (!((argv[2][i] >= L'0' && argv[2][i] <= L'9') ||
              (argv[2][i] >= L'a' && argv[2][i] <= L'f'))) {
            pt_diag_validation(PT_DG_PROBE_ARGUMENTS, 0); return 125;
        }
        nonce[i] = (char)argv[2][i];
    }
    nonce[32] = 0;
    depth = wcstoul(argv[3], &end, 10);
    if (*end || depth > 2) { pt_diag_validation(PT_DG_PROBE_ARGUMENTS, 0); return 125; }
    for (i = 0; i < 4; ++i) {
        ports[i] = wcstoul(argv[i + 4], &end, 10);
        if (*end || !ports[i] || ports[i] > 65535) {
            pt_diag_validation(PT_DG_PROBE_ARGUMENTS, 0); return 125;
        }
    }
    if (!pt_identity(GetCurrentProcess(), &identity)) return 125;
    identity.parent = pt_parent(identity.pid);
    if (!identity.parent) { pt_diag_validation(PT_DG_PROCESS_PARENT, identity.pid); return 125; }
    if (!lifetime) {
        error = WSAStartup(MAKEWORD(2, 2), &winsock);
        if (error != 0) { pt_diag_value(PT_DG_WINSOCK_STARTUP, PT_DK_WINSOCK, identity.pid, (DWORD)error); return 125; }
    }
    printf("{\"pid\":%lu,\"parent_pid\":%lu,\"created\":\"%llu\",\"depth\":%lu,"
           "\"nonce\":\"%s\",\"appcontainer\":%s,\"sid\":\"%ls\","
           "\"capability_count\":%lu,\"cases\":[",
           identity.pid, identity.parent, identity.created, depth, nonce,
           identity.appcontainer ? "true" : "false", identity.sid, identity.capabilities);
    if (!lifetime) {
        for (i = 0; i < 5; ++i) {
            error = socket_case(i == 1 || i == 3 ? AF_INET6 : AF_INET, i == 2 || i == 3, i == 4,
                                (unsigned short)(i < 4 ? ports[i] : 443), nonce);
            printf("%s{\"case\":\"%s\",\"status\":\"%s\",\"error\":%d}", i ? "," : "",
                   names[i], !error ? "connected" : error == WSAEACCES ? "denied" : "error", error);
        }
        if (WSACleanup() == SOCKET_ERROR) {
            error = WSAGetLastError();
            pt_diag_value(PT_DG_WINSOCK_CLEANUP, PT_DK_WINSOCK, identity.pid, (DWORD)error);
        }
    }
    printf("]}\n");
    fflush(stdout);
    if (depth < 2) {
        for (i = 0; i < 10; ++i) child_args[i] = argv[i];
        child_args[0] = argv[depth == 0 ? 8 : 9];
        depth_text[0] = (wchar_t)(L'1' + depth); depth_text[1] = 0;
        child_args[3] = depth_text;
        /* No security-capability override: this child must inherit its actual
           parent's AppContainer token, even from a different executable path. */
        if (!pt_spawn(10, child_args, NULL, input, &child)) { pt_diag_win32(PT_DG_CHILD_SPAWN, 0); return 125; }
        child_pid = child.identity.pid;
        if (ResumeThread(child.process.hThread) == (DWORD)-1) {
            pt_diag_win32(PT_DG_CHILD_RESUME, child_pid);
            if (!TerminateJobObject(child.job, 125)) pt_diag_win32(PT_DG_JOB_TERMINATE, child_pid);
            pt_finish(&child, 5000, &code, &expired);
            return 125;
        }
        if (!lifetime) {
            if (!pt_finish(&child, 120000, &code, &expired) || expired || code) {
                pt_diag_value(PT_DG_CHILD_FINISH, expired ? PT_DK_TIMEOUT : code ? PT_DK_CHILD_EXIT : PT_DK_VALIDATION,
                              child_pid, code);
                return 125;
            }
        }
    }
    if (lifetime) for (;;) Sleep(50);  /* Bounded externally; proves descendant termination. */
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    PT_STDIN input = {0};
    DWORD primary;
    int code;
    if (!pt_stdin_capture(&input)) return 125;
    code = pt_probe_main(argc, argv, &input);
    primary = GetLastError();
    if (!pt_stdin_release(&input)) {
        if (code) SetLastError(primary);
        return 125;
    }
    if (code) SetLastError(primary);
    return code;
}
