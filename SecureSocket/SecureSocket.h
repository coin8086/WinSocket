#pragma once

#include "common.h"

//SECURITY_WIN32 is required by sspi.h
#define SECURITY_WIN32
#include <sspi.h>

#include <Wincrypt.h>
#include "Socket.h"

namespace My {
    class SecureSocket : public Socket
    {
    public:
        SecureSocket(SOCKET s, bool server, const wchar_t * server_name = nullptr) :
            Socket(s), m_server(server), m_server_name(server_name) {}

        ~SecureSocket();

        bool init();

        virtual int send(const char* buf, int length) override;

        virtual int receive(char* buf, int length) override;

    private:
        bool negotiate_as_server();

        bool negotiate_as_client();

        bool create_server_cred();

        bool create_client_cred();

        bool m_server;
        const wchar_t* m_server_name;
        PCCERT_CONTEXT m_cert{};    //Only required by server
        CredHandle m_cred{};
        CtxtHandle m_ctx{};
        SecPkgContext_StreamSizes m_size{};
        static PSecurityFunctionTable sspi;
    };
}

