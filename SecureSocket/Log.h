#pragma once

#include <iostream>

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

