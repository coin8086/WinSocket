#include "SecureSocket.h"
#include "Certificate.h"

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
    return negotiate();
}

int My::SecureSocket::send(const char* buf, int length)
{
    return -1;
}

int My::SecureSocket::receive(char* buf, int length)
{
    return -1;
}

//Set m_ctx and m_size on success
bool My::SecureSocket::negotiate()
{
    return false;
}

//Set m_cred on success
bool My::SecureSocket::create_cred(const char * name)
{
    if (m_server && !name) {
        //Server socket must have a name and a certificate for that name, while it's optional for client.
        return false;
    }
    if (name) {
        m_cert = Certificate::get(name);
        if (!m_cert) {
            return false;
        }
    }
    return false;
}
