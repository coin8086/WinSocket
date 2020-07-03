#include "SecureSocket.h"
#include "Certificate.h"
#include <schannel.h>
#include <vector>
#include <cstring>
#include <cassert>
#include "Log.h"

#pragma comment(lib, "Secur32.lib")

PSecurityFunctionTable My::SecureSocket::sspi = nullptr;

My::SecureSocket::~SecureSocket()
{
    Log::info("[SecureSocket::~SecureSocket]");
    m_secured = false;
    if (sspi) {
        sspi->DeleteSecurityContext(&m_ctx);
        sspi->FreeCredentialsHandle(&m_cred);
    }
    if (m_cert) {
        Certificate::free(m_cert);
    }
}

//If init failed, the state of the object is undefined. Then a new object should be used to make
//a TLS connection, rather than call init again.
bool My::SecureSocket::init()
{
    if (m_secured) {
        return true;
    }
    //NOTE: A server name can be got by Server Name Indication(SNI) from a client in handshake. And
    //that requires parsing the ClientHello message and thus the knowledge of TLS record protocal.
    //Here we simplify the procedure by using a fixed name no matter what name the client requests.
    //And a client can refuse the server for a different name from the requested one, or accept it.
    //That depends on the client's choice, like accepting a self-issued certificate.
    if (m_server && !m_server_name) {
        //For server socket, a name is required to get a certificate associated with the name.
        //For client socket, it's optional.
        return false;
    }
    if (!sspi) {
        sspi = InitSecurityInterface();
        if (!sspi) {
            return false;
        }
    }
    return m_server ? create_server_cred() && negotiate_as_server() :
        create_client_cred() &&  negotiate_as_client();
}

int My::SecureSocket::send(const char* buf, int length)
{
    //NOTE: Should we split a long buf(longer than m_size.cbMaximumMessage) into small pieces to send one by one?
    //TODO: cbMaximumMessage includes the header and trailer, which should be reduced before comparing with length.
    if (!m_secured || !buf || length <= 0 || length > m_size.cbMaximumMessage) {
        return -1;
    }
    std::vector<char> send_buf(length + m_size.cbHeader + m_size.cbTrailer);
    memcpy(send_buf.data() + m_size.cbHeader, buf, length);

    SecBuffer out_buf[4];
    SecBufferDesc msg;

    msg.ulVersion = SECBUFFER_VERSION;
    msg.cBuffers = 4;
    msg.pBuffers = out_buf;

    out_buf[0].pvBuffer = send_buf.data();
    out_buf[0].cbBuffer = m_size.cbHeader;
    out_buf[0].BufferType = SECBUFFER_STREAM_HEADER;

    out_buf[1].pvBuffer = send_buf.data() + m_size.cbHeader;
    out_buf[1].cbBuffer = length;
    out_buf[1].BufferType = SECBUFFER_DATA;

    out_buf[2].pvBuffer = send_buf.data() + m_size.cbHeader + length;
    out_buf[2].cbBuffer = m_size.cbTrailer;
    out_buf[2].BufferType = SECBUFFER_STREAM_TRAILER;

    out_buf[3].BufferType = SECBUFFER_EMPTY;

    auto status = sspi->EncryptMessage(&m_ctx, 0, &msg, 0);
    int result = -1;
    if (SUCCEEDED(status))
    {
        int total = out_buf[0].cbBuffer + out_buf[1].cbBuffer + out_buf[2].cbBuffer;
        int sent = Socket::send(send_buf.data(), total);
        if (sent == total) {
            result = sent;
        }
        else {
            Log::error("[SecureSocket::send] Sent an encrypted message of", sent, " bytes. Should be ", total);
        }
    }
    else {
        Log::error("[SecureSocket::send] EncryptMessage failed with error: ", status);
    }
    return result;
}

int My::SecureSocket::receive(char* buf, int length)
{
    if (!m_secured || !buf || length <= 0) {
        return -1;
    }

    //NOTE: according to https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
    //there should only be 2 buffers here, and the second must be of type SECBUFFER_TOKEN with a "security token"(what?).
    SecBuffer in_buf[4];
    SecBufferDesc msg;
    msg.ulVersion = SECBUFFER_VERSION;
    msg.cBuffers = 4;
    msg.pBuffers = in_buf;

    SECURITY_STATUS status = SEC_E_INCOMPLETE_MESSAGE;

    int read = m_buf.size();
    if (read > 0) {
        //There are already some (extra) content received in buffer in previous call of receive, or from negotiation.
        in_buf[0].pvBuffer = m_buf.data();
        in_buf[0].cbBuffer = read;
        in_buf[0].BufferType = SECBUFFER_DATA;
        in_buf[1].BufferType = SECBUFFER_EMPTY;
        in_buf[2].BufferType = SECBUFFER_EMPTY;
        in_buf[3].BufferType = SECBUFFER_EMPTY;

        status = sspi->DecryptMessage(&m_ctx, &msg, 0, nullptr);
        Log::info("[SecureSocket::receive] DecryptMessage: ", status);
    }

    while (status == SEC_E_INCOMPLETE_MESSAGE)
    {
        if (read == m_buf.size()) {
            int to_size = m_buf.size() * 2;
            if (to_size < init_buf_size) {
                to_size = init_buf_size;
            }
            m_buf.resize(to_size);
        }

        int received = Socket::receive(m_buf.data() + read, m_buf.size() - read);
        if (received <= 0)
            break;
        read += received;

        in_buf[0].pvBuffer = m_buf.data();
        in_buf[0].cbBuffer = read;
        in_buf[0].BufferType = SECBUFFER_DATA;
        in_buf[1].BufferType = SECBUFFER_EMPTY;
        in_buf[2].BufferType = SECBUFFER_EMPTY;
        in_buf[3].BufferType = SECBUFFER_EMPTY;

        status = sspi->DecryptMessage(&m_ctx, &msg, 0, nullptr);
        Log::info("[SecureSocket::receive] DecryptMessage: ", status);
    }

    int result = -1;
    if (status == SEC_E_OK)
    {
        PSecBuffer data_buf = nullptr;
        for (int i = 1; i < 4; i++) //NOTE: Why from 1, not 0?
        {
            if (in_buf[i].BufferType == SECBUFFER_DATA)
            {
                data_buf = &in_buf[i];
                break;
            }
        }

        if (data_buf)
        {
            if (data_buf->cbBuffer > length) {
                //NOTE: Is there a way to avoid/alleviate the short-buffer problem?
                Log::error("[SecureSocket::receive] Input buffer is not big enough. At least ", data_buf->cbBuffer, " bytes is required.");
            }
            else {
                //NOTE: It seems the data_buf->pvBuffer points to an address in our m_buf.
                //Also note that data_buf->cbBuffer can be 0, according to the document.
                memcpy(buf, data_buf->pvBuffer, data_buf->cbBuffer);
                result = data_buf->cbBuffer;

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
                    Log::info("[SecureSocket::receive] Extra content of ", extra_buf->cbBuffer, " bytes is detected.");
                    //NOTE: Here memmove is used, rather than memcpy, because there may be overlap in src and dst.
                    assert(extra_buf->pvBuffer == m_buf.data() + read - extra_buf->cbBuffer);
                    memmove(m_buf.data(), extra_buf->pvBuffer, extra_buf->cbBuffer);
                    m_buf.resize(extra_buf->cbBuffer);
                }
                else {
                    m_buf.clear();
                }
            }
        }
    }
    else if (status == SEC_I_CONTEXT_EXPIRED) {
        Log::info("[SecureSocket::receive] SEC_I_CONTEXT_EXPIRED is received!");
        //TLS is shutting down.
        //NOTE: The document says we need to shutdown the TLS session:
        //https://docs.microsoft.com/en-us/windows/win32/secauthn/shutting-down-an-schannel-connection
        //However we simply skip the shutdown operation here and just mark the socket as "down".
        m_secured = false;
        result = -2;
    }
    else if (status == SEC_I_RENEGOTIATE) {
        Log::info("[SecureSocket::receive] SEC_I_RENEGOTIATE is received!");
        //NOTE: Renegotiation is not supported. User should shutdown the session in this case.
        m_secured = false;
        result = -3;
    }
    else {
        Log::error("[SecureSocket::receive] DecryptMessage failed with error: ", status);
    }
    if (result < 0) {
        m_buf.clear();
    }
    return result;
}

void My::SecureSocket::shutdown()
{
    if (!m_secured) {
        Socket::shutdown();
        return;
    }

    DWORD dwType = SCHANNEL_SHUTDOWN;
    SecBuffer out_buf[1];
    SecBufferDesc out_buf_desc;
    SECURITY_STATUS status;

    out_buf[0].pvBuffer = &dwType;
    out_buf[0].BufferType = SECBUFFER_TOKEN;
    out_buf[0].cbBuffer = sizeof(dwType);

    out_buf_desc.cBuffers = 1;
    out_buf_desc.pBuffers = out_buf;
    out_buf_desc.ulVersion = SECBUFFER_VERSION;

    status = sspi->ApplyControlToken(&m_ctx, &out_buf_desc);
    if (SUCCEEDED(status))
    {
        DWORD req_context_flags;
        if (m_server) {
            req_context_flags = ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_STREAM;
        }
        else {
            req_context_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        }
        DWORD ret_context_flags;
        TimeStamp ts;

        out_buf[0].pvBuffer = nullptr;
        out_buf[0].BufferType = SECBUFFER_TOKEN;
        out_buf[0].cbBuffer = 0;

        out_buf_desc.cBuffers = 1;
        out_buf_desc.pBuffers = out_buf;
        out_buf_desc.ulVersion = SECBUFFER_VERSION;

        //NOTE: It seems we need to a loop of calls to AcceptSecurityContext, according to
        //https://docs.microsoft.com/en-us/windows/win32/secauthn/shutting-down-an-schannel-connection
        //However we simply call it once here.
        if (m_server) {
            status = sspi->AcceptSecurityContext(
                &m_cred,
                &m_ctx,
                nullptr,
                req_context_flags,
                0,
                nullptr,
                &out_buf_desc,
                &ret_context_flags,
                &ts
            );
            if (FAILED(status)) {
                Log::warn("[SecureSocket::shutdown] AcceptSecurityContext failed with: ", status);
            }
        }
        else {
            status = sspi->InitializeSecurityContext(
                &m_cred,
                &m_ctx,
                nullptr,
                req_context_flags,
                0,
                0,
                nullptr,
                0,
                nullptr,
                &out_buf_desc,
                &ret_context_flags,
                &ts
            );
            if (FAILED(status)) {
                Log::warn("[SecureSocket::shutdown] InitializeSecurityContext failed with: ", status);
            }
        }

        if (out_buf[0].pvBuffer != nullptr && out_buf[0].cbBuffer != 0)
        {
            int sent = Socket::send((const char *)out_buf[0].pvBuffer, out_buf[0].cbBuffer);
            sspi->FreeContextBuffer(out_buf[0].pvBuffer);
            if (sent != out_buf[0].cbBuffer) {
                Log::warn("[SecureSocket::shutdown] send: ", sent, " total: ", out_buf[0].cbBuffer);
            }
        }
    }
    else {
        Log::warn("[SecureSocket::shutdown] ApplyControlToken failed with: ", status);
    }
    m_secured = false;
    Socket::shutdown();
}

bool My::SecureSocket::negotiate_as_server()
{
    bool ok = false;
    int read = 0;

    while (true) {
        //Increase buffer when necessary
        if (read == m_buf.size()) {
            int to_size = m_buf.size() * 2;
            if (to_size < init_buf_size) {
                to_size = init_buf_size;
            }
            m_buf.resize(to_size);
        }

        //Read in buffer
        int received = Socket::receive(m_buf.data() + read, m_buf.size() - read);
        if (received <= 0)
            break;
        read += received;

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
        in_buf[0].cbBuffer = read;
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
            auto sent = Socket::send((char *)out_buf[0].pvBuffer, out_buf[0].cbBuffer);
            sspi->FreeContextBuffer(out_buf[0].pvBuffer);
            if (sent != out_buf[0].cbBuffer) {
                Log::error("[SecureSocket::negotiate_as_server] sent: ", sent, " total: ", out_buf[0].cbBuffer);
                break;
            }
        }

        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            Log::info("[SecureSocket::negotiate_as_server] SEC_E_INCOMPLETE_MESSAGE");
            //Continue to read more...
            continue;
        }

        if (status == SEC_I_CONTINUE_NEEDED) {
            Log::info("[SecureSocket::negotiate_as_server] SEC_I_CONTINUE_NEEDED");
            //NOTE: Though it's less possible to have extra content in buffer when SEC_I_CONTINUE_NEEDED, it's still coded as is.
            if (in_buf[1].BufferType == SECBUFFER_EXTRA) {
                Log::info("[SecureSocket::negotiate_as_server] Extra content of ", in_buf[1].cbBuffer, " bytes is detected.");
                //Process any extra content read in before continue
                assert(m_buf.data() + read - in_buf[1].cbBuffer == in_buf[1].pvBuffer);
                memmove(m_buf.data(), in_buf[1].pvBuffer, in_buf[1].cbBuffer);
                read = in_buf[1].cbBuffer;
            }
            else {
                read = 0;
            }
            continue;
        }

        if (status == SEC_E_OK)
        {
            Log::info("[SecureSocket::negotiate_as_server] SEC_E_OK");
            if (in_buf[1].BufferType == SECBUFFER_EXTRA) {
                Log::info("[SecureSocket::negotiate_as_server] Extra content of ", in_buf[1].cbBuffer, " bytes is detected.");
                //Save any extra content read in
                //NOTE: Here memmove is used, rather than memcpy, because there may be overlap in src and dst.
                assert(m_buf.data() + read - in_buf[1].cbBuffer == in_buf[1].pvBuffer);
                memmove(m_buf.data(), in_buf[1].pvBuffer, in_buf[1].cbBuffer);
                m_buf.resize(in_buf[1].cbBuffer);
            }
            else {
                m_buf.clear();
            }
            ok = true;
            break;
        }

        Log::error("[SecureSocket::negotiate_as_server] AcceptSecurityContext failed with: ", status);
        break;
    }

    if (ok) {
        auto status = sspi->QueryContextAttributes(&m_ctx, SECPKG_ATTR_STREAM_SIZES, &m_size);
        if (status == SEC_E_OK) {
            m_secured = true;
        }
        else {
            Log::error("[SecureSocket::negotiate_as_server] QueryContextAttributes failed with: ", status);
            ok = false;
        }
    }

    if (!ok) {
        //Clear any content in buffer
        m_buf.clear();
    }
    return ok;
}

bool My::SecureSocket::negotiate_as_client()
{
    if (!send_client_hello()) {
        return false;
    }

    bool ok = false;
    int read = 0;

    while (true) {
        //Increase buffer when necessary
        if (read == m_buf.size()) {
            int to_size = m_buf.size() * 2;
            if (to_size < init_buf_size) {
                to_size = init_buf_size;
            }
            m_buf.resize(to_size);
        }

        //Read in buffer
        int received = Socket::receive(m_buf.data() + read, m_buf.size() - read);
        if (received <= 0)
            break;
        read += received;

        //InitializeSecurityContext
        //NOTE: Should we use the returned context flags from send_client_hello?
        DWORD req_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
            ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM |
            ISC_REQ_MANUAL_CRED_VALIDATION; // Allow manual validation of server certificate.
        DWORD ret_flags = 0;
        TimeStamp ts;

        SecBuffer in_buf[2];
        SecBuffer out_buf[1];
        SecBufferDesc in_buf_desc;
        SecBufferDesc out_buf_desc;

        in_buf[0].pvBuffer = m_buf.data();
        in_buf[0].cbBuffer = read;
        in_buf[0].BufferType = SECBUFFER_TOKEN;

        in_buf[1].pvBuffer = nullptr;
        in_buf[1].cbBuffer = 0;
        in_buf[1].BufferType = SECBUFFER_EMPTY;

        in_buf_desc.cBuffers = 2;
        in_buf_desc.pBuffers = in_buf;
        in_buf_desc.ulVersion = SECBUFFER_VERSION;

        out_buf[0].pvBuffer = nullptr;
        out_buf[0].BufferType = SECBUFFER_TOKEN;
        out_buf[0].cbBuffer = 0;

        out_buf_desc.cBuffers = 1;
        out_buf_desc.pBuffers = out_buf;
        out_buf_desc.ulVersion = SECBUFFER_VERSION;

        auto status = sspi->InitializeSecurityContext(
            &m_cred,
            &m_ctx,
            nullptr,
            req_flags,
            0,
            0,
            &in_buf_desc,
            0,
            nullptr,
            &out_buf_desc,
            &ret_flags,
            &ts
        );

        //Send content in out_buf if any
        if (out_buf[0].cbBuffer != 0 && out_buf[0].pvBuffer)
        {
            int sent = Socket::send((char *)out_buf[0].pvBuffer, out_buf[0].cbBuffer);
            sspi->FreeContextBuffer(out_buf[0].pvBuffer);
            if (sent != out_buf[0].cbBuffer)
            {
                Log::error("[SecureSocket::negotiate_as_client] sent: ", sent, " total: ", out_buf[0].cbBuffer);
                break;
            }
        }

        //Here we can validate server certificate by QueryContextAttributes with SECPKG_ATTR_REMOTE_CERT_CONTEXT.
        //If we don't do validation, then we accept any certificate server sent.
        //
        //PCCERT_CONTEXT server_cert = nullptr;
        //HRESULT hr = sspi->QueryContextAttributes(&m_cred, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &server_cert);
        //if (SUCCEEDED(hr)) {
        //    //Validate sever_cert here...
        //}

        //if status == SEC_I_INCOMPLETE_CREDENTIALS, it means server is requesting a client certificate.
        //Then we need to build a new client CredHandle with a certificate, and call InitializeSecurityContext
        //with the new CredHandle hereafter.

        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            Log::info("[SecureSocket::negotiate_as_client] SEC_E_INCOMPLETE_MESSAGE");
            continue;
        }

        if (status == SEC_I_CONTINUE_NEEDED) {
            Log::info("[SecureSocket::negotiate_as_client] SEC_I_CONTINUE_NEEDED");
            //NOTE: Though it's less possible to have extra content in buffer when SEC_I_CONTINUE_NEEDED, it's still coded as is.
            if (in_buf[1].BufferType == SECBUFFER_EXTRA) {
                Log::info("[SecureSocket::negotiate_as_client] Extra content of ", in_buf[1].cbBuffer, " bytes is detected.");
                //Process any extra content read in before continue
                assert(m_buf.data() + read - in_buf[1].cbBuffer == in_buf[1].pvBuffer);
                memmove(m_buf.data(), in_buf[1].pvBuffer, in_buf[1].cbBuffer);
                read = in_buf[1].cbBuffer;
            }
            else {
                read = 0;
            }
            continue;
        }

        if (status == SEC_E_OK)
        {
            Log::info("[SecureSocket::negotiate_as_client] SEC_E_OK");
            if (in_buf[1].BufferType == SECBUFFER_EXTRA) {
                Log::info("[SecureSocket::negotiate_as_client] Extra content of ", in_buf[1].cbBuffer, " bytes is detected.");
                //Save any extra content read in
                //NOTE: Here memmove is used, rather than memcpy, because there may be overlap in src and dst.
                assert(m_buf.data() + read - in_buf[1].cbBuffer == in_buf[1].pvBuffer);
                memmove(m_buf.data(), in_buf[1].pvBuffer, in_buf[1].cbBuffer);
                m_buf.resize(in_buf[1].cbBuffer);
            }
            else {
                m_buf.clear();
            }
            ok = true;
            break;
        }

        Log::error("[SecureSocket::negotiate_as_client] InitializeSecurityContext failed with: ", status);
        break;
    }

    if (ok) {
        auto status = sspi->QueryContextAttributes(&m_ctx, SECPKG_ATTR_STREAM_SIZES, &m_size);
        if (status == SEC_E_OK) {
            m_secured = true;
        }
        else {
            Log::error("[SecureSocket::negotiate_as_client] QueryContextAttributes failed with: ", status);
            ok = false;
        }
    }

    if (!ok) {
        //Clear any content in buffer
        m_buf.clear();
    }
    return ok;
}

//Also get m_ctx for client.
bool My::SecureSocket::send_client_hello()
{
    DWORD req_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
        ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM |
        ISC_REQ_MANUAL_CRED_VALIDATION; // Allow manual validation of server certificate.

    TimeStamp ts;
    SecBuffer out_buf[1];
    SecBufferDesc out_buf_desc;

    out_buf[0].pvBuffer = nullptr;
    out_buf[0].BufferType = SECBUFFER_TOKEN;
    out_buf[0].cbBuffer = 0;

    out_buf_desc.cBuffers = 1;
    out_buf_desc.pBuffers = out_buf;
    out_buf_desc.ulVersion = SECBUFFER_VERSION;

    auto status = sspi->InitializeSecurityContextW(
        &m_cred,
        nullptr,
        const_cast<wchar_t *>(m_server_name),
        req_flags,
        0,
        0,
        nullptr,
        0,
        &m_ctx,
        &out_buf_desc,
        &req_flags,
        &ts
    );

    bool ok = false;
    if (status == SEC_I_CONTINUE_NEEDED && out_buf[0].cbBuffer > 0 && out_buf[0].pvBuffer)
    {
        int sent = Socket::send((char*)out_buf[0].pvBuffer, out_buf[0].cbBuffer);
        sspi->FreeContextBuffer(out_buf[0].pvBuffer);
        if (sent == out_buf[0].cbBuffer)
        {
            ok = true;
        }
    }
    return ok;
}

bool My::SecureSocket::create_server_cred()
{
    m_cert = Certificate::get(m_server_name);
    if (!m_cert) {
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
    return (status == SEC_E_OK);
}

bool My::SecureSocket::create_client_cred()
{
    SCHANNEL_CRED schannel_cred{};
    TimeStamp ts;
    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    auto status = sspi->AcquireCredentialsHandle(
        nullptr,
        const_cast<_TCHAR*>(UNISP_NAME),
        SECPKG_CRED_OUTBOUND,
        nullptr,
        &schannel_cred,
        nullptr,
        nullptr,
        &m_cred,
        &ts
    );
    return (status == SEC_E_OK);
}
