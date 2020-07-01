#include "SecureSocket.h"
#include "Certificate.h"
#include <schannel.h>

#pragma comment(lib, "Secur32.lib")

PSecurityFunctionTable My::SecureSocket::sspi = nullptr;

My::SecureSocket::~SecureSocket()
{
    if (sspi) {
        sspi->DeleteSecurityContext(&m_ctx);
        sspi->FreeCredentialsHandle(&m_cred);
    }
    if (m_cert) {
        Certificate::free(m_cert);
    }
}

bool My::SecureSocket::init()
{
    if (!sspi) {
        sspi = InitSecurityInterface();
        if (!sspi) {
            return false;
        }
    }
    return m_server ? negotiate_as_server() : negotiate_as_client();
}

int My::SecureSocket::send(const char* buf, int length)
{
    return -1;
}

int My::SecureSocket::receive(char* buf, int length)
{
    return -1;
}

bool My::SecureSocket::negotiate_as_server()
{
    return false;
}

bool My::SecureSocket::negotiate_as_client()
{
    return false;
}

bool My::SecureSocket::create_server_cred(const wchar_t* server_name)
{
    m_cert = Certificate::get(server_name);
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

