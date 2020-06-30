#include "SecureSocket.h"

PSecurityFunctionTable My::SecureSocket::sspi = nullptr;

My::SecureSocket::~SecureSocket()
{
    if (sspi) {
        sspi->DeleteSecurityContext(&m_ctx);
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
