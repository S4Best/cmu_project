#include "Logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <iostream>

#define LOGGER_BUF_SIZE 2048

Logger::Logger()
    : printMsgFuncPtr(nullptr)
{
    printf("Logger()\n");
}

Logger::~Logger()
{
    printf("~Logger()\n");
}

void Logger::print(int flag, char* fmt, ...)
{
    std::string msg;

    int nSize = 0;
    char buff[LOGGER_BUF_SIZE];
    memset(buff, 0, sizeof(buff));
    va_list args;
    va_start(args, fmt);
    nSize = vsnprintf(buff, sizeof(buff), fmt, args);
    va_end(args);
    msg = std::string(buff);

    this->print(flag, msg);
}

void Logger::print(int flag, std::string msg)
{
    if (flag & mtype::mConsole)
    {
        std::cout << msg << std::endl;

        //TODO - save log console message
    }

    if (flag & mtype::mMsg )
    {
        if(printMsgFuncPtr)
            printMsgFuncPtr(mtype::mMsg, msg);
    }

    if (flag & mtype::mAlert)
    {
        if(printMsgFuncPtr)
            printMsgFuncPtr(mtype::mAlert, msg);

        //TODO - log alert with encryption
    }

    if (flag & mtype::mErrMsg)
    {
        std::string tmp = "[E] " + msg;
        std::cout << tmp << std::endl;
        if (printMsgFuncPtr)
            printMsgFuncPtr(mtype::mMsg, tmp);
    }

#ifdef LGC_TEST
    if (flag & mtype::mDebugConsole)
    {
        std::cout << "[DBG] " << msg << std::endl;
    }

    if (flag & mtype::mDebugMsg)
    {
        if (printMsgFuncPtr)
            printMsgFuncPtr(mtype::mMsg, "[DBG] " + msg);
    }
#endif
}