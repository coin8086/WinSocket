#pragma once

#include <iostream>
#include <cstdio>

namespace My {
    class Log
    {
    public:
        enum class Level {
            None = 0,
            Error,
            Warning,
            Info
        };

        static Level level;

        template <typename T, typename... Args>
        static void error(const T& msg, const Args&... args) {
            if (level < Level::Error) {
                return;
            }
            std::cerr << "[ERROR] ";
            output(msg, args...);
            std::cerr << std::endl;
        }

        template <typename T, typename... Args>
        static void warn(const T& msg, const Args&... args) {
            if (level < Level::Warning) {
                return;
            }
            std::cerr << "[WARNING] ";
            output(msg, args...);
            std::cerr << std::endl;
        }

        template <typename T, typename... Args>
        static void info(const T& msg, const Args&... args) {
            if (level < Level::Info) {
                return;
            }
            std::cerr << "[INFO] ";
            output(msg, args...);
            std::cerr << std::endl;
        }

        static void mem(const void * addr, size_t len) {
            if (level < Level::Info) {
                return;
            }
            fprintf(stderr, "[MEM] %u byte(s):", (int)len);
            const unsigned char* p = (const unsigned char *)addr;
            const size_t bytes_per_line = 16;
            for (size_t i = 0; i < len; i++) {
                if (i % bytes_per_line) {
                    fputc(' ', stderr);
                }
                else {
                    fputc('\n', stderr);
                }
                fprintf(stderr, "%02X", p[i]);
            }
            fputc('\n', stderr);
        }

    private:
        template <typename T>
        static void output(const T& msg) {
            std::cerr << msg;
        }

        template <typename T, typename... Args>
        static void output(const T& msg, const Args&... args) {
            std::cerr << msg;
            output(args...);
        }
    };
}

