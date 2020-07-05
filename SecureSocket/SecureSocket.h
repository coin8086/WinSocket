#pragma once

#include "common.h"

//SECURITY_WIN32 is required by sspi.h
#define SECURITY_WIN32
#include <sspi.h>

#include <Wincrypt.h>
#include "Socket.h"
#include <vector>


namespace My {
    class SecureSocket : public Socket
    {
    public:
        SecureSocket(SOCKET s, bool server, const wchar_t * server_name = nullptr) :
            Socket(s), m_server(server), m_server_name(server_name) {}

        ~SecureSocket();

        bool init();

        virtual int max_message_size() override;

        virtual int send(const char* buf, int length) override;

        virtual int receive(char* buf, int length) override;

        virtual void shutdown() override;

    private:
        bool negotiate_as_server();

        bool negotiate_as_client();

        bool send_client_hello();

        bool create_server_cred();

        bool create_client_cred();

        inline int max_payload() {
            return m_size.cbMaximumMessage - m_size.cbHeader - m_size.cbTrailer;
        }

        bool m_secured = false;
        bool m_server;
        const wchar_t* m_server_name;
        PCCERT_CONTEXT m_cert{};    //Only required by server
        CredHandle m_cred{};
        CtxtHandle m_ctx{};
        SecPkgContext_StreamSizes m_size{};
        //TODO: do not resize m_buf frequently.
        std::vector<char> m_buf;
        static PSecurityFunctionTable sspi;
        //NOTE: 16KiB is the max size of a TLS message, bigger buf may incur some performance loss 
        //due to moving extra content in m_buf after one message is processed.
        static const int init_buf_size = 1024 * 16;
    };
}

