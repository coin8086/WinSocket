#pragma once

#include <iostream>

namespace My {
    class Log
    {
    public:
        template <typename T, typename... Args>
        static void error(const T& msg, const Args&... args) {
            std::cerr << "[ERROR] ";
            output(msg, args...);
            std::cerr << std::endl;
        }

        template <typename T, typename... Args>
        static void warn(const T& msg, const Args&... args) {
            std::cerr << "[WARNING] ";
            output(msg, args...);
            std::cerr << std::endl;
        }

        template <typename T, typename... Args>
        static void info(const T& msg, const Args&... args) {
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

