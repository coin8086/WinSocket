#include "ServerSocket.h"
#include "Event.h"
#include "Log.h"
#include "..\SecureSocket\Certificate.h"
#include <schannel.h>
#include <cassert>

using My::Certificate;

#pragma comment(lib, "Secur32.lib")

PSecurityFunctionTable ServerSocket::sspi = nullptr;

ServerSocket* ServerSocket::create(HANDLE iocp, SOCKET socket, IServerSocketHandler* handler, const wchar_t* server_name)
{
    assert(iocp && socket && handler);
    auto obj = new ServerSocket(iocp, socket, handler, server_name);
    auto result = CreateIoCompletionPort((HANDLE)socket, iocp, (ULONG_PTR)obj, 0);
    if (!result) {
        LOG_ERROR("CreateIoCompletionPort failed with error: ", GetLastError());
        obj->m_handler = nullptr; //Do not delete handler then.
        delete obj;
        return nullptr;
    }
    return obj;
}

ServerSocket::~ServerSocket()
{
    LOG_INFO("");
    shutdown();
    delete m_handler;
}

bool ServerSocket::start()
{
    if (m_state != State::Init) {
        LOG_ERROR("Invalid state.");
        return false;
    }
    return m_tls_enabled ? tls_start() : start_at_once();
}

bool ServerSocket::start_at_once()
{
    assert(m_state == State::Init);
    m_state = State::Started;
    m_handler->on_started(this);
    return true;
}

void ServerSocket::shutdown()
{
    if (m_state == State::Started) {
        m_tls_enabled ? tls_shutdown() : shutdown_at_once();
    }
}

void ServerSocket::shutdown_at_once()
{
    ::shutdown(m_socket, SD_BOTH);
    ::closesocket(m_socket);
    m_state = State::Shutdown;
    m_handler->on_shutdown(this);
}

bool ServerSocket::receive(char* buf, size_t size)
{
    if (m_state != State::Started) {
        LOG_ERROR("Invalid state.");
        return false;
    }
    return m_tls_enabled ? tls_start_receive(buf, size, false) : start_receive(buf, size);
}

bool ServerSocket::start_receive(char* buf, size_t size)
{
    assert(m_state == State::Started && buf && size);
    auto event = new ReceiveEvent(this, buf, size);
    DWORD flags = 0;
    WSABUF wsabuf;
    wsabuf.buf = buf;
    wsabuf.len = size;
    auto result = WSARecv(m_socket, &wsabuf, 1, nullptr, &flags, event, nullptr);
    if (result == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
        LOG_ERROR("WSARecv failed with error: ", WSAGetLastError());
        delete event;
        return false;
    }
    return true;
}

bool ServerSocket::tls_start_receive(char* user_buf, size_t user_buf_size, bool force_start)
{
    assert(m_state == State::Started && user_buf && user_buf_size);
    if (!force_start && m_buf_used > 0) {
        tls_do_receive(user_buf, user_buf_size, 0);
        //Error will be handled by user handler if any. Returning true mimics starting an async sending without error.
        return true;
    }
    if (InterlockedCompareExchange(&m_tls_receiving, 1, 0)) {
        assert(0 && "Concurrent receiving is not supported.");
        return false;
    }
    //We don't use user buf for receiving TLS message. But we save it in a ReceiveEvent for later use.
    resize_buf_when_necessary();
    auto event = new ReceiveEvent(this, user_buf, user_buf_size);
    DWORD flags = 0;
    WSABUF wsabuf;
    wsabuf.buf = m_buf.data() + m_buf_used;
    wsabuf.len = m_buf.size() - m_buf_used;
    auto result = WSARecv(m_socket, &wsabuf, 1, nullptr, &flags, event, nullptr);
    if (result == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
        LOG_ERROR("WSARecv failed with error: ", WSAGetLastError());
        InterlockedExchange(&m_tls_receiving, 0);
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
        LOG_ERROR("WSAGetOverlappedResult failed with error: ", WSAGetLastError());
        delete event;
        return;
    }
    if (!io_size) {
        LOG_INFO("Client is shutting down.");
        delete event;
        shutdown();
        return;
    }
    if (m_tls_enabled) {
        tls_do_receive(event->m_buf, event->m_size, io_size);
    }
    else {
        m_handler->on_received(this, event->m_buf, event->m_size, io_size);
    }
    delete event;
}

void ServerSocket::tls_do_receive(char* user_buf, size_t user_buf_size, size_t received)
{
    InterlockedExchange(&m_tls_receiving, 0);

    assert(m_state == State::Started);

    m_buf_used += received;

    //NOTE: according to https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
    //there should only be 2 buffers here, and the second must be of type SECBUFFER_TOKEN with a "security token"(what?).
    SecBuffer in_buf[4];
    SecBufferDesc msg;
    msg.ulVersion = SECBUFFER_VERSION;
    msg.cBuffers = 4;
    msg.pBuffers = in_buf;

    SECURITY_STATUS status = SEC_E_INCOMPLETE_MESSAGE;

    if (m_buf_used > 0) {
        //There are already some (extra) content received in buffer in previous call of receive, or from negotiation.
        in_buf[0].pvBuffer = m_buf.data();
        in_buf[0].cbBuffer = (unsigned long)m_buf_used;
        in_buf[0].BufferType = SECBUFFER_DATA;
        in_buf[1].BufferType = SECBUFFER_EMPTY;
        in_buf[2].BufferType = SECBUFFER_EMPTY;
        in_buf[3].BufferType = SECBUFFER_EMPTY;

        status = sspi->DecryptMessage(&m_ctx, &msg, 0, nullptr);
        LOG_VERBOSE("DecryptMessage: ", status);
    }

    if (status == SEC_E_INCOMPLETE_MESSAGE) {
        if (!tls_start_receive(user_buf, user_buf_size, true)) {
            m_handler->on_error(this);
        }
        return;
    }

    if (status == SEC_I_CONTEXT_EXPIRED) {
        LOG_INFO("SEC_I_CONTEXT_EXPIRED is received!");
        //TLS is shutting down.
        tls_shutdown();
        return;
    }

    if (status == SEC_I_RENEGOTIATE) {
        LOG_INFO("SEC_I_RENEGOTIATE is received!");
        //NOTE: Renegotiation is not supported. We shutdown the session in this case.
        tls_shutdown();
        return;
    }

    if (status != SEC_E_OK) {
        LOG_ERROR("DecryptMessage failed with error: ", status);
        m_handler->on_error(this);
        return;
    }

    PSecBuffer data_buf = nullptr;
    for (int i = 1; i < 4; i++) //NOTE: Why from 1, not 0?
    {
        if (in_buf[i].BufferType == SECBUFFER_DATA)
        {
            data_buf = &in_buf[i];
            break;
        }
    }

    if (!data_buf)
    {
        m_handler->on_error(this);
        return;
    }

    if (data_buf->cbBuffer > user_buf_size) {
        //NOTE: Is there a way to avoid/alleviate the short-buffer problem?
        LOG_ERROR("Input buffer is not big enough. At least ", data_buf->cbBuffer, " bytes is required.");
        m_handler->on_error(this);
        return;
    }

    //NOTE: It seems the data_buf->pvBuffer points to an address in our m_buf.
    //Also note that data_buf->cbBuffer can be 0, according to the document. HOWEVER, receiving zero-size buf
    //is a sign of SHUTDOWN for plain socket recv call. And we'd better have the same semantics for higher level
    //user no matter TLS is on or off.
    if (data_buf->cbBuffer == 0) {
        LOG_WARN("received zero-size message payload.");
    }
    memcpy(user_buf, data_buf->pvBuffer, data_buf->cbBuffer);
    size_t result = data_buf->cbBuffer;

    //Save extra content read in buf
    PSecBuffer extra_buf = nullptr;
    for (int i = 1; i < 4; i++)
    {
        if (in_buf[i].BufferType == SECBUFFER_EXTRA)
        {
            extra_buf = &in_buf[i];
            break;
        }
    }
    if (extra_buf)
    {
        LOG_INFO("Extra content of ", extra_buf->cbBuffer, " bytes is detected.");
        //NOTE: Here memmove is used, rather than memcpy, because there may be overlap in src and dst.
        assert(extra_buf->pvBuffer == m_buf.data() + m_buf_used - extra_buf->cbBuffer);
        memmove(m_buf.data(), extra_buf->pvBuffer, extra_buf->cbBuffer);
        //m_buf.resize(extra_buf->cbBuffer);
        m_buf_used = extra_buf->cbBuffer;
    }
    else {
        //m_buf.clear();
        m_buf_used = 0;
    }

    m_handler->on_received(this, user_buf, user_buf_size, result);
}

bool ServerSocket::send(const char* buf, size_t size)
{
    if (m_state != State::Started) {
        LOG_ERROR("Invalid state.");
        return false;
    }
    return m_tls_enabled ? tls_start_send(buf, size) : start_send(buf, size);
}

bool ServerSocket::start_send(const char* buf, size_t size)
{
    assert(m_state == State::Started);
    auto event = new SendEvent(this, buf, size);
    WSABUF wsabuf;
    wsabuf.buf = (char*)buf;
    wsabuf.len = size;
    auto result = WSASend(m_socket, &wsabuf, 1, nullptr, 0, event, nullptr);
    if (result == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
        LOG_ERROR("WSASend failed with error: ", WSAGetLastError());
        delete event;
        return false;
    }
    return true;
}

bool ServerSocket::tls_start_send(const char* buf, size_t size)
{
    assert(m_state == State::Started);

    size_t send_size = max_payload();
    if (send_size > size) {
        send_size = size;
    }
    size_t ensure_size = send_size + m_size.cbHeader + m_size.cbTrailer;
    if (ensure_size < init_buf_size) {
        ensure_size = init_buf_size;
    }
    m_send_buf.resize(ensure_size);
    memcpy(m_send_buf.data() + m_size.cbHeader, buf, send_size);

    SecBuffer out_buf[4];
    SecBufferDesc msg;

    msg.ulVersion = SECBUFFER_VERSION;
    msg.cBuffers = 4;
    msg.pBuffers = out_buf;

    out_buf[0].pvBuffer = m_send_buf.data();
    out_buf[0].cbBuffer = m_size.cbHeader;
    out_buf[0].BufferType = SECBUFFER_STREAM_HEADER;

    out_buf[1].pvBuffer = m_send_buf.data() + m_size.cbHeader;
    out_buf[1].cbBuffer = send_size;
    out_buf[1].BufferType = SECBUFFER_DATA;

    out_buf[2].pvBuffer = m_send_buf.data() + m_size.cbHeader + send_size;
    out_buf[2].cbBuffer = m_size.cbTrailer;
    out_buf[2].BufferType = SECBUFFER_STREAM_TRAILER;

    out_buf[3].BufferType = SECBUFFER_EMPTY;

    auto status = sspi->EncryptMessage(&m_ctx, 0, &msg, 0);
    if (FAILED(status)) {
        LOG_ERROR("EncryptMessage failed with error: ", status);
        //m_send_buf.clear();
        return false;
    }

    if (InterlockedCompareExchange(&m_tls_sending, 1, 0)) {
        assert(0 && "Concurrent sending is not supported.");
        return false;
    }

    size_t total = out_buf[0].cbBuffer + out_buf[1].cbBuffer + out_buf[2].cbBuffer;
    auto event = new TlsSendEvent(this, buf, size, send_size, total);
    WSABUF wsabuf;
    wsabuf.buf = m_send_buf.data();
    wsabuf.len = total;
    auto result = WSASend(m_socket, &wsabuf, 1, nullptr, 0, event, nullptr);
    if (result == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
        LOG_ERROR("WSASend failed with error: ", WSAGetLastError());
        InterlockedExchange(&m_tls_sending, 0);
        delete event;
        return false;
    }
    return true;
}

void ServerSocket::do_send_event(SendEvent* event)
{
    DWORD io_size;
    DWORD flags;
    if (!WSAGetOverlappedResult(m_socket, event, &io_size, FALSE, &flags)) {
        LOG_ERROR("WSAGetOverlappedResult failed with error: ", WSAGetLastError());
        delete event;
        return;
    }
    if (m_tls_enabled) {
        tls_do_send((TlsSendEvent*)event, io_size);
    }
    else {
        m_handler->on_sent(this, event->m_buf, event->m_size, io_size);
    }
    delete event;
}

void ServerSocket::tls_do_send(TlsSendEvent* event, size_t sent)
{
    InterlockedExchange(&m_tls_sending, 0);
    if (sent == event->m_encrypted_send_size) {
        m_handler->on_sent(this, event->m_buf, event->m_size, event->m_send_size);
    }
    else {
        m_handler->on_error(this);
    }
}

bool ServerSocket::tls_start()
{
    assert(m_state == State::Init);
    if (!tls_init()) {
        return false;
    }
    m_buf_used = 0;
    if (!tls_start_handshake_receive()) {
        return false;
    }
    m_state = State::HandShake;
    return true;
}

bool ServerSocket::tls_init()
{
    if (!sspi) {
        sspi = InitSecurityInterface();
        if (!sspi) {
            return false;
        }
    }
    return create_server_cred();
}

//Start a handshake receive with internal m_buf starting at (m_buf.data() + m_buf_used).
bool ServerSocket::tls_start_handshake_receive()
{
    assert(m_buf_used <= m_buf.size());
    resize_buf_when_necessary();
    auto event = new HandshakeReceiveEvent(this, m_buf.data() + m_buf_used, m_buf.size() - m_buf_used);
    DWORD flags = 0;
    WSABUF wsabuf;
    wsabuf.buf = m_buf.data() + m_buf_used;
    wsabuf.len = m_buf.size() - m_buf_used;
    auto result = WSARecv(m_socket, &wsabuf, 1, nullptr, &flags, event, nullptr);
    if (result == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
        LOG_ERROR("WSARecv failed with error: ", WSAGetLastError());
        delete event;
        return false;
    }
    return true;
}

bool ServerSocket::tls_start_handshake_send(const char* buf, size_t size)
{
    auto event = new HandshakeSendEvent(this, buf, size);
    WSABUF wsabuf;
    wsabuf.buf = (char*)buf;
    wsabuf.len = size;
    auto result = WSASend(m_socket, &wsabuf, 1, nullptr, 0, event, nullptr);
    if (result == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
        LOG_ERROR("WSASend failed with error: ", WSAGetLastError());
        delete event;
        return false;
    }
    return true;
}

void ServerSocket::do_handshake_receive_event(HandshakeReceiveEvent* event)
{
    DWORD io_size;
    DWORD flags;
    bool error = !WSAGetOverlappedResult(m_socket, event, &io_size, FALSE, &flags);
    delete event;
    if (error) {
        LOG_ERROR("WSAGetOverlappedResult failed with error: ", WSAGetLastError());
        m_handler->on_error(this);
        return;
    }

    m_buf_used += io_size;

    //AcceptSecurityContext
    DWORD req_context_flags = ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
        ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_STREAM;
    DWORD ret_context_flags = 0;
    TimeStamp ts;

    //NOTE: Shall we have a third in-buffer of type SECBUFFER_ALERT as said in
    //https://docs.microsoft.com/en-us/windows/win32/secauthn/acceptsecuritycontext--schannel ?
    SecBuffer in_buf[2];
    SecBuffer out_buf[1];
    SecBufferDesc in_buf_desc;
    SecBufferDesc out_buf_desc;

    in_buf[0].pvBuffer = m_buf.data();
    in_buf[0].cbBuffer = m_buf_used;
    in_buf[0].BufferType = SECBUFFER_TOKEN;

    in_buf[1].pvBuffer = nullptr;
    in_buf[1].cbBuffer = 0;
    in_buf[1].BufferType = SECBUFFER_EMPTY;

    out_buf[0] = {};

    in_buf_desc.cBuffers = 2;
    in_buf_desc.pBuffers = in_buf;
    in_buf_desc.ulVersion = SECBUFFER_VERSION;

    out_buf_desc.cBuffers = 1;
    out_buf_desc.pBuffers = out_buf;
    out_buf_desc.ulVersion = SECBUFFER_VERSION;

    auto status = sspi->AcceptSecurityContext(
        &m_cred,
        m_ctx.dwLower != 0 || m_ctx.dwUpper != 0 ? &m_ctx : nullptr,
        &in_buf_desc,
        req_context_flags,
        0,
        m_ctx.dwLower != 0 || m_ctx.dwUpper != 0 ? nullptr : &m_ctx,
        &out_buf_desc,
        &ret_context_flags,
        &ts
    );

    //Send content in out_buf if any
    if (out_buf[0].cbBuffer != 0 && out_buf[0].pvBuffer != nullptr)
    {
        if (!tls_start_handshake_send((char*)out_buf[0].pvBuffer, out_buf[0].cbBuffer)) {
            LOG_ERROR("Failed sending out handshake message.");
            sspi->FreeContextBuffer(out_buf[0].pvBuffer);
            m_handler->on_error(this);
            return;
        }
    }

    if (status == SEC_E_INCOMPLETE_MESSAGE) {
        LOG_INFO("SEC_E_INCOMPLETE_MESSAGE");
        tls_start_handshake_receive();
        return;
    }

    if (status == SEC_I_CONTINUE_NEEDED) {
        LOG_INFO("SEC_I_CONTINUE_NEEDED");
        if (in_buf[1].BufferType == SECBUFFER_EXTRA) {
            LOG_ERROR("Extra content of ", in_buf[1].cbBuffer, " bytes is detected.");
            m_handler->on_error(this);
        }
        else {
            m_buf_used = 0;
            tls_start_handshake_receive();
        }
        return;
    }

    if (status != SEC_E_OK)
    {
        LOG_ERROR("AcceptSecurityContext failed with: ", status);
        m_handler->on_error(this);
        return;
    }

    LOG_INFO("SEC_E_OK");
    if (in_buf[1].BufferType == SECBUFFER_EXTRA) {
        LOG_INFO("Extra content of ", in_buf[1].cbBuffer, " bytes is detected.");
        //Save any extra content read in
        //NOTE: Here memmove is used, rather than memcpy, because there may be overlap in src and dst.
        memmove(m_buf.data(), m_buf.data() + m_buf_used - in_buf[1].cbBuffer, in_buf[1].cbBuffer);
        //m_buf.resize(in_buf[1].cbBuffer);
        m_buf_used = in_buf[1].cbBuffer;
    }
    else {
        //m_buf.clear();
        m_buf_used = 0;
    }

    status = sspi->QueryContextAttributes(&m_ctx, SECPKG_ATTR_STREAM_SIZES, &m_size);
    if (status != SEC_E_OK) {
        LOG_ERROR("QueryContextAttributes failed with: ", status);
        m_handler->on_error(this);
        return;
    }

    m_state = State::Started;
    m_handler->on_started(this);
}

void ServerSocket::do_handshake_send_event(HandshakeSendEvent* event)
{
    DWORD io_size;
    DWORD flags;
    bool error = !WSAGetOverlappedResult(m_socket, event, &io_size, FALSE, &flags) || io_size != event->m_size;
    sspi->FreeContextBuffer(event->m_buf);  //TODO: Some way to ensure the buf gets freed?
    delete event;
    if (error) {
        LOG_ERROR("WSAGetOverlappedResult failed with error: ", WSAGetLastError());
        m_handler->on_error(this);
        return;
    }
}

void ServerSocket::tls_shutdown()
{
    //TODO: Graceful shutdown by sending shutdown message...
    shutdown_at_once();
}

bool ServerSocket::create_server_cred()
{
    m_cert = Certificate::get(m_server_name);
    if (!m_cert) {
        //TODO: Log can output wstring.
        LOG_ERROR("Server certificate is not found!");
        return false;
    }
    SCHANNEL_CRED schannel_cred{};
    TimeStamp ts;
    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    schannel_cred.cCreds = 1;
    schannel_cred.paCred = &m_cert;
    //NOTE: by https://docs.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-schannel_cred
    //"
    //If this member is zero, Schannel selects the protocol. For new development, applications should
    //set grbitEnabledProtocols to zero and use the protocol versions enabled on the system by default.
    //This member is used only by the Microsoft Unified Security Protocol Provider security package.
    //The global system registry settings take precedence over this value. For example, if SSL3 is
    //disabled in the registry, it cannot be enabled using this member.
    //"
    schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
    //NOTE: Do we need to set this and what will happen when the session expires?
    //schannel_cred.dwSessionLifespan = ?
    schannel_cred.dwFlags = SCH_USE_STRONG_CRYPTO;
    auto status = sspi->AcquireCredentialsHandle(
        nullptr,
        const_cast<_TCHAR*>(UNISP_NAME),    //NOTE: What about SCHANNEL_NAME?
        SECPKG_CRED_INBOUND,
        nullptr,
        &schannel_cred,
        nullptr,
        nullptr,
        &m_cred,
        &ts
    );
    if (status != SEC_E_OK) {
        if (status == SEC_E_UNKNOWN_CREDENTIALS) {
            LOG_ERROR("AcquireCredentialsHandle failed with SEC_E_UNKNOWN_CREDENTIALS. The server certificate is probabaly invalid!");
        }
        else {
            LOG_ERROR("AcquireCredentialsHandle failed with: ", status);
        }
    }
    return (status == SEC_E_OK);
}
