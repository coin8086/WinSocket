#include "Common.h"
#include <ws2tcpip.h>
#include <process.h>
#include "Log.h"
#include "ServerSocket.h"
#include "EchoServer.h"
#include "Event.h"

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_PORT "27015"
#define MAX_WORKERS 64
#define BUF_SIZE (1024 * 16)

SOCKET create_server_socket() {
    struct addrinfo hints = {}; //ZeroMemory
    struct addrinfo * addr = NULL;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    auto result = getaddrinfo(NULL, DEFAULT_PORT, &hints, &addr);
    if (result != 0) {
        Log::error("getaddrinfo failed with error: ", result);
        return INVALID_SOCKET;
    }

    //NOTE: socket implicilty has WSA_FLAG_OVERLAPPED set as:
    //auto listen_socket = WSASocket(addr->ai_family, addr->ai_socktype, addr->ai_protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
    auto listen_socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (listen_socket == INVALID_SOCKET) {
        Log::error("socket failed with error: ", WSAGetLastError());
        freeaddrinfo(addr);
        return INVALID_SOCKET;
    }

    result = bind(listen_socket, addr->ai_addr, (int)addr->ai_addrlen);
    freeaddrinfo(addr);
    if (result == SOCKET_ERROR) {
        Log::error("bind failed with error: ", WSAGetLastError());
        closesocket(listen_socket);
        return INVALID_SOCKET;
    }

    result = listen(listen_socket, SOMAXCONN);
    if (result == SOCKET_ERROR) {
        Log::error("listen failed with error: ", WSAGetLastError());
        closesocket(listen_socket);
        return INVALID_SOCKET;
    }
    return listen_socket;
}

unsigned int __stdcall iocp_worker(void* arg);

HANDLE g_workers[MAX_WORKERS] = {};
size_t g_worker_count = 0;

bool create_iocp_workers(HANDLE iocp) {
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    g_worker_count = system_info.dwNumberOfProcessors * 2;
    if (g_worker_count > MAX_WORKERS) {
        g_worker_count = MAX_WORKERS;
    }
    for (size_t i = 0; i < g_worker_count; i++) {
        g_workers[i] = (HANDLE)_beginthreadex(nullptr, 0, iocp_worker, iocp, 0, nullptr);
        if (!g_workers[i]) {
            Log::error("_beginthreadex failed with error: ", GetLastError());
            return false;
        }
    }
    return true;
}

void stop_iocp_workers(HANDLE iocp) {
    for (size_t i = 0; i < g_worker_count; i++) {
        PostQueuedCompletionStatus(iocp, 0, 0, 0);
    }
    WaitForMultipleObjects(g_worker_count, g_workers, TRUE, 1000 * 3);
    for (size_t i = 0; i < g_worker_count; i++) {
        CloseHandle(g_workers[i]);
    }
}

bool g_exit = false;

BOOL WINAPI CtrlHandler(DWORD event) {
    Log::info("Terminating...");
    g_exit = true;
    Sleep(1000 * 5);
    return FALSE; //Let default handler terminate the process
}

int main(int argc, char ** argv) {
    if (!Log::init()) {
        return 1;
    }
    Log::level = Log::Level::Info;

    bool using_tls = false;
    if (argc == 2 && strcmp(argv[1], "-t") == 0) {
        using_tls = true;
    }

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        Log::error("SetConsoleCtrlHandler failed with error: ", GetLastError());
        return 1;
    }

    auto iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!iocp) {
        Log::error("CreateIoCompletionPort failed with error: ", GetLastError());
        return 1;
    }

    if (!create_iocp_workers(iocp)) {
        CloseHandle(iocp);
        return 1;
    }

    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        Log::error("WSAStartup failed with error: ", result);
        stop_iocp_workers(iocp);
        CloseHandle(iocp);
        return 1;
    }

    SOCKET server_socket = create_server_socket();
    if (server_socket == INVALID_SOCKET) {
        stop_iocp_workers(iocp);
        CloseHandle(iocp);
        WSACleanup();
        return 1;
    }

    u_long nonblock = 1;
    result = ioctlsocket(server_socket, FIONBIO, &nonblock);
    if (result == SOCKET_ERROR) {
        Log::error("ioctlsocket failed with error: ", WSAGetLastError());
        stop_iocp_workers(iocp);
        CloseHandle(iocp);
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    while (!g_exit) {
        //NOTE: A better way is to use WSAEventSelect for socket and wait on FD_ACCEPT event.
        //Here we just sleep for simplicity.
        Sleep(20);

        //NOTE: Could also be:
        //auto socket = WSAAccept(server_socket, nullptr, nullptr, nullptr, 0);
        //if (socket == SOCKET_ERROR) {
        auto socket = accept(server_socket, nullptr, 0);
        if (socket == INVALID_SOCKET) {
            if (WSAEWOULDBLOCK != WSAGetLastError()) {
                Log::error("accept failed with error: ", WSAGetLastError());
            }
            continue;
        }

        Log::info("Accepted a connection.");

        //TODO: Some way to clean up handler and server in some exception cases, say iocp is closed.
        auto handler = new EchoServer(BUF_SIZE);
        auto server = ServerSocket::create(iocp, socket, handler, using_tls ? L"localhost" : nullptr);
        if (!server->start()) {
            delete server;
            delete handler;
        }
    }

    Log::info("Shutting down server socket...");
    shutdown(server_socket, SD_BOTH);
    closesocket(server_socket);
    Log::info("Stopping IOCP workers...");
    stop_iocp_workers(iocp);
    CloseHandle(iocp);
    WSACleanup();
    return 0;
}

unsigned int __stdcall iocp_worker(void* arg) {
    HANDLE iocp = (HANDLE)arg;
    while (true) {
        DWORD io_size;
        ServerSocket * socket;
        LPOVERLAPPED overlapped;
        if (!GetQueuedCompletionStatus(iocp, &io_size, (PULONG_PTR)&socket, &overlapped, INFINITE)) {
            Log::warn("GetQueuedCompletionStatus failed with error: ", GetLastError());
            if (GetLastError() == ERROR_ABANDONED_WAIT_0) { //ERROR_ABANDONED_WAIT_0 means iocp has been closed.
                break;
            }
        }

        if (!socket && !overlapped) {
            Log::info("Worker is stopping...");
            break;
        }

        //NOTE: Here compiler knows how to adjust pointer to overlapped for pointer to Event, while
        //it doesn't know if &event was passed to GetQueuedCompletionStatus as (LPOVERLAPPED *).
        Event* event = (Event *)overlapped;
        event->run();
    }
    return 1; //Success, while 0 indicates an error
}
