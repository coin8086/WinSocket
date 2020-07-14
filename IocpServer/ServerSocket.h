#pragma once

#include "Common.h"


class ServerSocket;

//NOTE: For a callback on_xxx, the ServerSocket may be deleted from inside it. ServerSocket
//should hanlde such case properly.
class ISocketHandler
{
public:
    virtual void on_started(ServerSocket* socket) = 0;

    virtual void on_shutdown(ServerSocket* socket) = 0;

    virtual void on_received(ServerSocket* socket, char* buf, size_t size, size_t received) = 0;

    virtual void on_sent(ServerSocket* socket, const char* buf, size_t size, size_t sent) = 0;

    virtual ~ISocketHandler() {}
};

class ReceiveEvent;
class SendEvent;

class ServerSocket
{
    friend class ReceiveEvent;
    friend class SendEvent;

public:
    enum class State {
        Init = 0,
        Started,
        Shutdown
    };

    static ServerSocket* create(HANDLE iocp, SOCKET socket, ISocketHandler * handler);

    ~ServerSocket();

    bool start();

    void shutdown();

    bool receive(char* buf, size_t size);

    bool send(const char* buf, size_t size);

private:
    ServerSocket(HANDLE iocp, SOCKET socket, ISocketHandler* handler) : m_iocp(iocp), m_socket(socket), m_handler(handler) {}

    void do_receive_event(ReceiveEvent* event);

    void do_send_event(SendEvent* event);

    HANDLE m_iocp;
    SOCKET m_socket;
    ISocketHandler* m_handler;
    State m_state = State::Init;
};

