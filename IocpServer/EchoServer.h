#pragma once

#include "ServerSocket.h"
#include <vector>

class EchoServer : public ISocketHandler
{
public:
    EchoServer(size_t buf_size) {
        m_buf.resize(buf_size);
    }

    ~EchoServer();

    virtual void on_started(ServerSocket* socket) override;

    virtual void on_shutdown(ServerSocket* socket) override;

    virtual void on_received(ServerSocket* socket, char* buf, size_t size, size_t received) override;

    virtual void on_sent(ServerSocket* socket, const char* buf, size_t size, size_t sent) override;

    virtual void on_error(ServerSocket* socket) override;

private:
    std::vector<char> m_buf;
};

