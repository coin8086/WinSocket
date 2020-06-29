#pragma once

#include "common.h"
#include "ISocket.h"

namespace My {
    class SecureSocket : public ISocket
    {
    public:
        SecureSocket(SOCKET s) : m_s(s) {}

        virtual int send(const char* buf, int length) override;

        virtual int receive(char* buf, int length) override;

    private:
        SOCKET m_s;
    };
}

