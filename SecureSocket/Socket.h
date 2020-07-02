#pragma once

#include "common.h"
#include "ISocket.h"

namespace My {
    class Socket : public ISocket
    {
    public:
        explicit Socket(SOCKET s): m_s(s) {}

        Socket(const Socket&) = delete;

        Socket & operator = (const Socket&) = delete;

        virtual int send(const char* buf, int length) override;

        virtual int receive(char* buf, int length) override;

        virtual void shutdown() override;

    private:
        SOCKET m_s;
    };
}

