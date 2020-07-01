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
        SecureSocket(SOCKET s, bool server) : Socket(s), m_server(server) {}

        ~SecureSocket();

        bool init();

        virtual int send(const char* buf, int length) override;

        virtual int receive(char* buf, int length) override;

    private:
        bool negotiate();

        bool create_cred(const wchar_t * name);

        bool m_server;
        PCCERT_CONTEXT m_cert{};
        CredHandle m_cred{};
        CtxtHandle m_ctx{};
        SecPkgContext_StreamSizes m_size{};
        static PSecurityFunctionTable sspi;
    };
}

