#include "EchoServer.h"
#include "Log.h"


EchoServer::~EchoServer()
{
    LOG_INFO("");
}

void EchoServer::on_started(ServerSocket* socket)
{
    LOG_VERBOSE("Start receiving...");
    if (!socket->receive(m_buf.data(), m_buf.size())) {
        LOG_ERROR("receive failed!");
        socket->shutdown();
    }
}

void EchoServer::on_shutdown(ServerSocket* socket)
{
    LOG_VERBOSE("Nothing to do.");
    //NOTE: Delete the socket in the shutdown handler once and avoid deleting the socket multiple times.
    delete socket;
}

void EchoServer::on_received(ServerSocket* socket, char* buf, size_t size, size_t received)
{
    LOG_VERBOSE("received: ", received);
    if (!socket->send(buf, received)) {
        socket->shutdown();
    }
}

void EchoServer::on_sent(ServerSocket* socket, const char* buf, size_t size, size_t sent)
{
    LOG_VERBOSE("sent: ", sent, "target: ", size);
    if (size > sent) {
        if (!socket->send(buf + sent, size - sent)) {
            socket->shutdown();
        }
    }
    else {
        if (!socket->receive(m_buf.data(), m_buf.size())) {
            socket->shutdown();
        }
    }
}

void EchoServer::on_error(ServerSocket* socket)
{
    LOG_ERROR("ServerSocket error in state: ", (int)socket->get_state());
    socket->shutdown();
}
