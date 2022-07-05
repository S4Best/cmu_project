#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>

namespace mtype {
    static int mConsole         = 0b00000001;       /* console --> will be replaced with log */
    static int mMsg             = 0b00000010;       /* ui - normal */
    static int mAlert           = 0b00000100;       /* ui - alert */
    static int mDebugConsole    = 0b00001000;       /* debug in console */
    static int mDebugMsg        = 0b00010000;       /* debug in ui */
    static int mErrMsg          = 0b00100000;       /* err in console and ui */
    static int mMsgWithConsole  = mConsole | mMsg;  /* ui(msg) + console */
    static int mDebug           = mDebugConsole | mDebugMsg;    /* debug in ui(msg)+console */
    static int mAlertAll        = mAlert | mMsgWithConsole;     /* ui(alert) + ui((msg) + console */
};

typedef void (*print_msg_func)(int flag, std::string msg);

class Logger
{
public:
    static Logger& getInstance()
    {
        static Logger    instance; // Guaranteed to be destroyed.
                              // Instantiated on first use.
        return instance;
    }

private:
    Logger();                    // Constructor? (the {} brackets) are needed here.
    ~Logger();

    print_msg_func printMsgFuncPtr;

    // C++ 11
    // =======
    // We can use the better technique of deleting the methods
    // we don't want.
public:
    Logger(Logger const&) = delete;
    void operator=(Logger const&) = delete;

    // Note: Scott Meyers mentions in his Effective Modern
    //       C++ book, that deleted functions should generally
    //       be public as it results in better error messages
    //       due to the compilers behavior to check accessibility
    //       before deleted status
    void print(int flag, char *fmt, ...);
    void print(int flag, std::string msg);
    void setPrintMsgFunc(print_msg_func pmf) { printMsgFuncPtr = pmf; }
    
};

#define MSG(flag, fmt, ...) Logger::getInstance().print(flag, fmt, ##__VA_ARGS__)

#endif