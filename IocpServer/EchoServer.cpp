#include "EchoServer.h"
#include "Log.h"


EchoServer::~EchoServer()
{
    Log::info("[EchoServer::~EchoServer]");
}

void EchoServer::on_started(ServerSocket* socket)
{
    Log::verbose("[EchoServer::on_started] Start receiving...");
    if (!socket->receive(m_buf.data(), m_buf.size())) {
        Log::error("[EchoServer::on_started] receive failed!");
        socket->shutdown();
        delete socket;
    }
}

void EchoServer::on_shutdown(ServerSocket* socket)
{
    Log::verbose("[EchoServer::on_shutdown] Nothing to do.");
}

void EchoServer::on_received(ServerSocket* socket, char* buf, size_t size, size_t received)
{
    Log::verbose("[EchoServer::on_received] received: ", received);
    if (!socket->send(buf, received)) {
        socket->shutdown();
        delete socket;
    }
}

void EchoServer::on_sent(ServerSocket* socket, const char* buf, size_t size, size_t sent)
{
    Log::verbose("[EchoServer::on_sent] sent: ", sent, "target: ", size);
    if (size > sent) {
        if (!socket->send(buf + sent, size - sent)) {
            socket->shutdown();
            delete socket;
        }
    }
    else {
        if (!socket->receive(m_buf.data(), m_buf.size())) {
            socket->shutdown();
            delete socket;
        }
    }
}
