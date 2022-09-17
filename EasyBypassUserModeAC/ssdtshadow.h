#ifndef _SSDTSHOWD_H
#define _SSDTSHOW_H

#include "_global.h"
#include "hooklib.h"

class SSDTSHADOW
{
public:
    static PVOID GetFunctionAddress(const char* apiname);
    static HOOK Hook(const char* apiname, void* newfunc);
    static void Hook(HOOK hHook);
    static void Unhook(HOOK hHook, bool free = false);
};

#endif