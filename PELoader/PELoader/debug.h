#pragma once

//注意需要在format前后加空格 C++11的新特性导致的
#define __CSZQDEBUG 1
#if __CSZQDEBUG > 0
#define DBGPRINT(format, ...)   printf("[DEBUG]%s:%d :" format  , __func__, __LINE__, ##__VA_ARGS__);
#define PRINTDBG printf("[DEBUG]%s:%d\r\n", __FUNCTION__, __LINE__);
#else
#define DBGPRINT(format, ...)
#define PRINTDBG
#endif