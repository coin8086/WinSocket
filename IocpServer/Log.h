#pragma once

#include "Common.h"
#include <iostream>

class Log
{
private:
    class AutoLock {
    public:
        AutoLock(CRITICAL_SECTION * cs) : m_cs(cs) {
            EnterCriticalSection(m_cs);
        }

        ~AutoLock() {
            LeaveCriticalSection(m_cs);
        }

    private:
        CRITICAL_SECTION * m_cs;
    };

public:
    enum class Level {
        None = 0,
        Error,
        Warning,
        Info,
        Verbose
    };

    static Level level;

    static bool init();

    template <typename T, typename... Args>
    static void error(const T& msg, const Args&... args) {
        if (level < Level::Error) {
            return;
        }
        AutoLock l(&lock);
        output_prefix("ERROR");
        output(msg, args...);
        std::cerr << std::endl;
    }

    template <typename T, typename... Args>
    static void warn(const T& msg, const Args&... args) {
        if (level < Level::Warning) {
            return;
        }
        AutoLock l(&lock);
        output_prefix("WARNING");
        output(msg, args...);
        std::cerr << std::endl;
    }

    template <typename T, typename... Args>
    static void info(const T& msg, const Args&... args) {
        if (level < Level::Info) {
            return;
        }
        AutoLock l(&lock);
        output_prefix("INFO");
        output(msg, args...);
        std::cerr << std::endl;
    }

    template <typename T, typename... Args>
    static void verbose(const T& msg, const Args&... args) {
        if (level < Level::Verbose) {
            return;
        }
        AutoLock l(&lock);
        output_prefix("VERBOSE");
        output(msg, args...);
        std::cerr << std::endl;
    }

private:
    static inline void output_prefix(const char * level) {
        std::cerr << "[" << level << "] [" << GetCurrentThreadId() << "] ";
    }

    template <typename T>
    static void output(const T& msg) {
        std::cerr << msg;
    }

    template <typename T, typename... Args>
    static void output(const T& msg, const Args&... args) {
        std::cerr << msg;
        output(args...);
    }

    static CRITICAL_SECTION lock;
};
