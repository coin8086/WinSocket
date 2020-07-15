#pragma once

#include "Common.h"

//SECURITY_WIN32 is required by sspi.h
#define SECURITY_WIN32
#include <sspi.h>
#include <Wincrypt.h>
#include <vector>

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

    virtual void on_error(ServerSocket* socket) = 0;    //It's for error in handshake now, and may include other errors in the future.

    virtual ~ISocketHandler() {}
};

class ReceiveEvent;
class SendEvent;
class HandshakeReceiveEvent;
class HandshakeSendEvent;
class TlsSendEvent;

class ServerSocket
{
    friend class ReceiveEvent;
    friend class SendEvent;
    friend class HandshakeReceiveEvent;
    friend class HandshakeSendEvent;
    friend class TlsSendEvent;

public:
    enum class State {
        Init = 0,
        HandShake,
        Started,
        Shutdown
    };

    static ServerSocket* create(HANDLE iocp, SOCKET socket, ISocketHandler * handler, const wchar_t * server_name = nullptr);

    ~ServerSocket();

    bool start();

    void shutdown();

    bool receive(char* buf, size_t size);

    bool send(const char* buf, size_t size);

    State get_state() const {
        return m_state;
    }

private:
    ServerSocket(HANDLE iocp, SOCKET socket, ISocketHandler* handler, const wchar_t * server_name) : 
        m_iocp(iocp), m_socket(socket), m_handler(handler), m_server_name(server_name), m_tls_enabled(server_name) {}

    bool start_at_once();

    void shutdown_at_once();

    bool start_receive(char* buf, size_t size);

    bool tls_start_receive(char* buf, size_t size, bool force_start);

    void do_receive_event(ReceiveEvent* event);

    void tls_do_receive(char* buf, size_t size, size_t received);

    bool start_send(const char* buf, size_t size);

    bool tls_start_send(const char* buf, size_t size);

    void do_send_event(SendEvent* event);

    void tls_do_send(TlsSendEvent* event, size_t sent);

    bool tls_start();

    bool tls_init();

    bool tls_start_handshake_receive();

    bool tls_start_handshake_send(const char * buf, size_t size);

    void do_handshake_receive_event(HandshakeReceiveEvent* event);

    void do_handshake_send_event(HandshakeSendEvent* event);

    void tls_shutdown();

    inline size_t max_payload() {
        return m_size.cbMaximumMessage - m_size.cbHeader - m_size.cbTrailer;
    }

    inline void resize_buf_when_necessary() {
        if (m_buf_used == m_buf.size()) {
            auto to_size = m_buf.size() * 2;
            if (to_size < init_buf_size) {
                to_size = init_buf_size;
            }
            m_buf.resize(to_size);
        }
    }

    bool create_server_cred();

    HANDLE m_iocp;
    SOCKET m_socket;
    ISocketHandler* m_handler;
    State m_state = State::Init;

    //The following fields are for TLS
    bool m_tls_enabled;
    const wchar_t* m_server_name;
    PCCERT_CONTEXT m_cert{};
    CredHandle m_cred{};    //NOTE: the cred can be saved and reused for other sockets.
    CtxtHandle m_ctx{};
    SecPkgContext_StreamSizes m_size{};

    std::vector<char> m_buf;
    size_t m_buf_used = 0;
    long m_tls_receiving = 0;

    std::vector<char> m_send_buf;
    long m_tls_sending = 0;

    static PSecurityFunctionTable sspi;
    //NOTE: 16KiB is the max size of a TLS message, bigger buf may incur some performance loss 
    //due to moving extra content in m_buf after one message is processed.
    static const int init_buf_size = 1024 * 16;
};

