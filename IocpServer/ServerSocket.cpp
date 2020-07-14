#include "ServerSocket.h"
#include "Event.h"
#include "Log.h"
#include <cassert>

ServerSocket* ServerSocket::create(HANDLE iocp, SOCKET socket, ISocketHandler* handler)
{
    assert(iocp && socket && handler);
    auto obj = new ServerSocket(iocp, socket, handler);
    auto result = CreateIoCompletionPort((HANDLE)socket, iocp, (ULONG_PTR)obj, 0);
    if (!result) {
        Log::error("[ServerSocket::create] CreateIoCompletionPort failed with error: ", GetLastError());
        obj->m_handler = nullptr; //Do not delete handler then.
        delete obj;
        return nullptr;
    }
    return obj;
}

ServerSocket::~ServerSocket()
{
    Log::info("[ServerSocket::~ServerSocket]");
    shutdown();
    delete m_handler;
}

bool ServerSocket::start()
{
    if (m_state != State::Init) {
        Log::error("[ServerSocket::start] Invalid state.");
        return false;
    }
    m_state = State::Started;
    m_handler->on_started(this);
    return true;
}

void ServerSocket::shutdown()
{
    if (m_state == State::Started) {
        ::shutdown(m_socket, SD_BOTH);
        ::closesocket(m_socket);
        m_state = State::Shutdown;
        m_handler->on_shutdown(this);
    }
}

bool ServerSocket::receive(char* buf, size_t size)
{
    if (m_state != State::Started) {
        Log::error("[ServerSocket::receive] Invalid state.");
        return false;
    }
    auto event = new ReceiveEvent(this, buf, size);
    DWORD flags = 0;
    WSABUF wsabuf;
    wsabuf.buf = buf;
    wsabuf.len = size;
    auto result = WSARecv(m_socket, &wsabuf, 1, nullptr, &flags, event, nullptr);
    if (result == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
        Log::error("[ServerSocket::receive] WSARecv failed with error: ", WSAGetLastError());
        delete event;
        return false;
    }
    return true;
}

bool ServerSocket::send(const char* buf, size_t size)
{
    if (m_state != State::Started) {
        Log::error("[ServerSocket::send] Invalid state.");
        return false;
    }
    auto event = new SendEvent(this, buf, size);
    WSABUF wsabuf;
    wsabuf.buf = (char *)buf;
    wsabuf.len = size;
    auto result = WSASend(m_socket, &wsabuf, 1, nullptr, 0, event, nullptr);
    if (result == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
        Log::error("[ServerSocket::send] WSASend failed with error: ", WSAGetLastError());
        delete event;
        return false;
    }
    return true;
}

void ServerSocket::do_receive_event(ReceiveEvent* event)
{
    DWORD io_size;
    DWORD flags;
    if (!WSAGetOverlappedResult(m_socket, event, &io_size, FALSE, &flags)) {
        Log::error("[ServerSocket::do_receive_event] WSAGetOverlappedResult failed with error: ", WSAGetLastError());
        delete event;
        return;
    }
    if (!io_size) {
        Log::info("[ServerSocket::do_receive_event] Client is shutting down.");
        delete event;
        shutdown();
        delete this;
        return;
    }
    m_handler->on_received(this, event->m_buf, event->m_size, io_size);
    delete event;
}

void ServerSocket::do_send_event(SendEvent* event)
{
    DWORD io_size;
    DWORD flags;
    if (!WSAGetOverlappedResult(m_socket, event, &io_size, FALSE, &flags)) {
        Log::error("[ServerSocket::do_send_event] WSAGetOverlappedResult failed with error: ", WSAGetLastError());
        delete event;
        return;
    }
    m_handler->on_sent(this, event->m_buf, event->m_size, io_size);
    delete event;
}