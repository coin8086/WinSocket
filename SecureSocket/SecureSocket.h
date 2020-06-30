#pragma once

#include "common.h"

//SECURITY_WIN32 is required by sspi.h
#define SECURITY_WIN32
#include <sspi.h>

#include <Wincrypt.h>
#include "ISocket.h"

namespace My {
    class SecureSocket : public ISocket
    {
    public:
        SecureSocket(SOCKET s, bool server) : m_s(s), m_server(server) {}

        ~SecureSocket();

        bool init();

        virtual int send(const char* buf, int length) override;

        virtual int receive(char* buf, int length) override;

    private:
        bool negotiate();

        bool create_cred(const char* name);

        SOCKET m_s;
        bool m_server;
        PCCERT_CONTEXT m_cert{};
        CredHandle m_cred{};
        CtxtHandle m_ctx{};
        SecPkgContext_StreamSizes m_size{};
        static PSecurityFunctionTable sspi;
    };
}

