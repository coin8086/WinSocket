#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <memory>
#include <vector>

#include "..\SecureSocket\Log.h"
#include "..\SecureSocket\Socket.h"
#include "..\SecureSocket\SecureSocket.h"

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 8192
#define DEFAULT_PORT "27015"

int __cdecl main(int argc, char** argv)
{
    //My::Log::level = My::Log::Level::Info;

    WSADATA wsa_data;
    int result;

    SOCKET listen_socket = INVALID_SOCKET;
    SOCKET accept_socket = INVALID_SOCKET;

    struct addrinfo hints;
    struct addrinfo* addr = NULL;

    bool using_tls = false;
    if (argc == 2 && strcmp(argv[1], "-t") == 0) {
        using_tls = true;
    }

    // Initialize Winsock
    result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        printf("WSAStartup failed with error: %d\n", result);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    result = getaddrinfo(NULL, DEFAULT_PORT, &hints, &addr);
    if (result != 0) {
        printf("getaddrinfo failed with error: %d\n", result);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    listen_socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (listen_socket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(addr);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    result = bind(listen_socket, addr->ai_addr, (int)addr->ai_addrlen);
    if (result == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(addr);
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(addr);

    result = listen(listen_socket, SOMAXCONN);
    if (result == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    accept_socket = accept(listen_socket, NULL, NULL);
    if (accept_socket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(listen_socket);

    int buf_size = DEFAULT_BUFLEN;
    std::vector<char> buf;
    std::unique_ptr<My::ISocket> server = nullptr;
    if (using_tls) {
        My::Log::info("[main] Enabling TLS...");
        auto ss = new My::SecureSocket(accept_socket, true, L"localhost");
        if (!ss->init()) {
            My::Log::error("[main] Init TLS failed!");
            delete ss;
            closesocket(accept_socket);
            WSACleanup();
            return 1;
        }
        My::Log::info("[main] TLS is enabled!");
        server = std::unique_ptr<My::ISocket>(ss);
        buf_size = server->max_message_size();
    }
    else {
        My::Log::info("[main] No TLS!");
        server = std::unique_ptr<My::ISocket>(new My::Socket(accept_socket));
    }
    buf.resize(buf_size);

    //Since we're going to ouput bianry to stdout.
    _setmode(_fileno(stdout), _O_BINARY);

    // Receive until the peer shuts down the connection
    while (true) {
        result = server->receive(buf.data(), (int)buf.size());
        if (result > 0) {
            if (!std::cout.write(buf.data(), result)) {
                My::Log::error("[main] Failed writing to output file!");
                break;
            }
            int sent = server->send(buf.data(), result);
            if (sent != result) {
                My::Log::error("[main] sent: ", sent, " expected: ", result);
                break;
            }
        }
        else if (result < 0) {
            if (result == -2) {
                My::Log::info("[main] Client is shutting down.");
            }
            else {
                My::Log::error("[main] receive failed with error: ", result);
            }
            break;
        }
        else if (!using_tls) {
            My::Log::info("[main] Client is shuttig down.");
            break;
        }
    }

    My::Log::info("[main] Shutting down...");
    std::cout.flush();
    server->shutdown();

    // cleanup
    closesocket(accept_socket);
    WSACleanup();

    return 0;
}
