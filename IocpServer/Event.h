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

protected:
    ReceiveEvent(ServerSocket* s, char* buf, size_t size) : IoEvent(s, buf, size) {}
};

class SendEvent : public IoEvent
{
    friend class ServerSocket;

public:
    virtual void run() override {
        m_server->do_send_event(this);
    }

protected:
    SendEvent(ServerSocket* s, const char* buf, size_t size) : IoEvent(s, (char *)buf, size) {}
};

class HandshakeReceiveEvent : public ReceiveEvent
{
    friend class ServerSocket;

public:
    virtual void run() override {
        m_server->do_handshake_receive_event(this);
    }

protected:
    HandshakeReceiveEvent(ServerSocket* s, char* buf, size_t size) : ReceiveEvent(s, buf, size) {}
};

class HandshakeSendEvent : public SendEvent
{
    friend class ServerSocket;

public:
    virtual void run() override {
        m_server->do_handshake_send_event(this);
    }

protected:
    HandshakeSendEvent(ServerSocket* s, const char* buf, size_t size) : SendEvent(s, buf, size) {}
};