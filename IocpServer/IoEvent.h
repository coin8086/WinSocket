#pragma once

#include "Common.h"
#include <vector>

class IoEvent : public OVERLAPPED
{
public:
    enum class Type {
        Undefined = 0,
        Read,
        Write
    };

    typedef std::vector<char> Buffer;

    IoEvent(Type t): m_type(t) {
        //reset_overlapped();
    }

    void reset_overlapped() {
        ZeroMemory((OVERLAPPED *)this, sizeof(OVERLAPPED));
    }

    Buffer & get_buf(size_t size) {
        m_buf.resize(size);
        return m_buf;
    }

    Buffer & get_buf() {
        return m_buf;
    }

    const Buffer & get_buf() const {
        return m_buf;
    }

    Type get_type() const {
        return m_type;
    }

    void set_type(Type t) {
        m_type = t;
    }

    size_t get_buf_received() const {
        return m_buf_received;
    }

    void set_buf_received(size_t received) {
        m_buf_received = received;
    }

    size_t get_buf_sent() const {
        return m_buf_sent;
    }

    void set_buf_sent(size_t sent) {
        m_buf_sent = sent;
    }

private:
    Type m_type;
    Buffer m_buf;
    size_t m_buf_received = 0;
    size_t m_buf_sent = 0;
};

