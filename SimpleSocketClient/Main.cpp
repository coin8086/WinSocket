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


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 8192
#define FILE_BUFLEN 20000
#define DEFAULT_PORT "27015"

//The file stream must be already in binary mode.
int get_file_size(std::istream & is) {
    auto pos = is.tellg();
    is.seekg(0, is.end);
    int size = is.tellg();
    is.seekg(pos);
    return size;
}

bool send_all(My::ISocket * s, const char * buf, int size) {
    while (size > 0) {
        int sent = s->send(buf, size);
        if (sent < 0) {
            break;
        }
        buf += sent;
        size -= sent;
    }
    return size == 0;
}

int __cdecl main(int argc, char** argv)
{
    WSADATA wsa_data;
    SOCKET connect_socket = INVALID_SOCKET;
    struct addrinfo* addr = NULL,
        * ptr = NULL,
        hints;
    int result;

    // Validate the parameters
    if (argc < 2) {
        printf("usage: %s server-name [-t]\n", argv[0]);
        return 1;
    }

    bool using_tls = false;
    if (argc == 3 && strcmp(argv[2], "-t") == 0) {
        using_tls = true;
    }

    // Initialize Winsock
    result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        printf("WSAStartup failed with error: %d\n", result);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    result = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &addr);
    if (result != 0) {
        printf("getaddrinfo failed with error: %d\n", result);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = addr; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        connect_socket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (connect_socket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        result = connect(connect_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (result == SOCKET_ERROR) {
            closesocket(connect_socket);
            connect_socket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(addr);

    if (connect_socket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    int buf_size = DEFAULT_BUFLEN;
    std::vector<char> buf;
    std::unique_ptr<My::ISocket> client = nullptr;
    if (using_tls) {
        My::Log::info("[main] Enabling TLS...");
        auto ss = new My::SecureSocket(connect_socket, false);
        if (!ss->init()) {
            My::Log::error("[main] Init TLS failed!");
            delete ss;
            closesocket(connect_socket);
            WSACleanup();
            return 1;
        }
        My::Log::info("[main] TLS is enabled!");
        client = std::unique_ptr<My::ISocket>(ss);
        buf_size = client->max_message_size();
    }
    else {
        My::Log::info("[main] No TLS!");
        client = std::unique_ptr<My::ISocket>(new My::Socket(connect_socket));
    }

    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);

    const int file_size = get_file_size(std::cin);
    if (file_size <= 0) {
        My::Log::error("[main] Invalid std input!");
        closesocket(connect_socket);
        WSACleanup();
        return 1;
    }

    char input[FILE_BUFLEN];
    int left = file_size;
    while (left > 0) {
        int read = left > FILE_BUFLEN ? FILE_BUFLEN : left;
        if (!std::cin.read(input, read)) {
            My::Log::error("[main] Bad read!");
            break;
        }
        left -= read;
        if (!send_all(client.get(), input, read)) {
            My::Log::error("[main] Bad send!");
            break;
        }
    }

    if (left > 0) {
        My::Log::error("[main] Send failed!");
        closesocket(connect_socket);
        WSACleanup();
        return 1;
    }

    // Receive until the peer closes the connection
    buf.resize(buf_size);
    int received = 0;
    while (received < file_size) {
        result = client->receive(buf.data(), buf_size);
        if (result > 0) {
            received += result;
            if (!std::cout.write(buf.data(), result)) {
                My::Log::error("[main] failed writing to output file!");
                break;
            }
        }
        else if (result < 0) {
            My::Log::warn("[main] receive failed with error: ", result);
            break;
        }
        else if (!using_tls) {
            My::Log::info("[main] server is shuttig down.");
            break;
        }
    }

    My::Log::info("[main] Shutting down...");
    std::cout.flush();
    client->shutdown();

    // cleanup
    closesocket(connect_socket);
    WSACleanup();

    return 0;
}
