#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory>

#include "..\SecureSocket\Socket.h"
#include "..\SecureSocket\SecureSocket.h"


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 8192
#define DEFAULT_PORT "27015"

int __cdecl main(int argc, char** argv)
{
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL,
        * ptr = NULL,
        hints;
    const char* sendbuf = "this is a test";
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    // Validate the parameters
    if (argc < 2) {
        printf("usage: %s server-name [-t]\n", argv[0]);
        return 1;
    }

    bool usingTLS = false;
    if (argc == 3 && strcmp(argv[2], "-t") == 0) {
        usingTLS = true;
    }

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    std::unique_ptr<My::ISocket> client = nullptr;
    if (usingTLS) {
        printf("Enabling TLS...\n");
        auto ss = new My::SecureSocket(ConnectSocket, false);
        if (!ss->init()) {
            printf("Init TLS failed!");
            delete ss;
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }
        else {
            printf("TLS is enabled!");
        }
        client = std::unique_ptr<My::ISocket>(ss);
    }
    else {
        printf("No TLS!\n");
        client = std::unique_ptr<My::ISocket>(new My::Socket(ConnectSocket));
    }

    // Send an initial buffer
    iResult = client->send(sendbuf, (int)strlen(sendbuf));
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    printf("Bytes Sent: %ld\n", iResult);

    // Receive until the peer closes the connection
    do {
        iResult = client->receive(recvbuf, recvbuflen);
        if (iResult >= 0)
            printf("Bytes received: %d\n", iResult);
        else
            printf("recv failed with error: %d\n", iResult);
    } while (iResult >= 0);

    client->shutdown();

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}