#pragma once

#include "common.h"
#include "ISocket.h"

namespace My {
    class Socket : public ISocket
    {
    public:
        Socket(SOCKET s): m_s(s) {}

        virtual int send(const char* buf, int length) override;

        virtual int receive(char* buf, int length) override;

    private:
        SOCKET m_s;
    };
}

