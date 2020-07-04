#pragma once

namespace My {
    class ISocket
    {
    public:
        virtual int max_message_size() = 0;

        virtual int send(const char * buf, int length) = 0;

        virtual int receive(char* buf, int length) = 0;

        virtual void shutdown() = 0;

        virtual ~ISocket() {}
    };
}