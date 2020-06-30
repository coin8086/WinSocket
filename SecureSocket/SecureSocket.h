#pragma once

#include "common.h"
#include <sspi.h>
#include "ISocket.h"

namespace My {
    class SecureSocket : public ISocket
    {
    public:
        SecureSocket(SOCKET s) : m_s(s), m_ctx({}) {}

        ~SecureSocket();

        bool init();

        virtual int send(const char* buf, int length) override;

        virtual int receive(char* buf, int length) override;

    private:
        bool negotiate();

        SOCKET m_s;
        CtxtHandle m_ctx;
        SecPkgContext_StreamSizes m_size;
        static PSecurityFunctionTable sspi;
    };
}

