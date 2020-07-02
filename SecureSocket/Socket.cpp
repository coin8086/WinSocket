#include "Socket.h"

int My::Socket::send(const char* buf, int length)
{
    return ::send(m_s, buf, length, 0);
}

int My::Socket::receive(char* buf, int length)
{
    return ::recv(m_s, buf, length, 0);
}

void My::Socket::shutdown()
{
    ::shutdown(m_s, SD_SEND);
}
