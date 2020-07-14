#pragma once

#include "Common.h"
#include "ServerSocket.h"

class Event : public OVERLAPPED
{
public:
    virtual void run() = 0;

    virtual ~Event() {}
};

class IoEvent : public Event 
{
    friend class ServerSocket;

protected:
    IoEvent(ServerSocket * s, char * buf, size_t size) : m_server(s), m_buf(buf), m_size(size) {}

    ServerSocket * m_server;
    char* m_buf;
    size_t m_size;
};

class ReceiveEvent : public IoEvent
{
    friend class ServerSocket;

public:
    virtual void run() override {
        m_server->do_receive_event(this);
    }

private:
    ReceiveEvent(ServerSocket* s, char* buf, size_t size) : IoEvent(s, buf, size) {}
};

class SendEvent : public IoEvent
{
    friend class ServerSocket;

public:
    virtual void run() override {
        m_server->do_send_event(this);
    }

private:
    SendEvent(ServerSocket* s, const char* buf, size_t size) : IoEvent(s, (char *)buf, size) {}
};
