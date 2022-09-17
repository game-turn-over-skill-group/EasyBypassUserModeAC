#ifndef _MISC_H
#define _MISC_H

#include "_global.h"

class Misc
{
public:
    static ULONG GetProcessIDFromProcessHandle(HANDLE ProcessHandle);
    static ULONG GetProcessIDFromThreadHandle(HANDLE ThreadHandle);
    static UCHAR* PsGetProcessImageFileName2(PEPROCESS EProcess);
    static UCHAR* GetProcessNameFromPid(HANDLE Pid);
    static ULONG FindProcess(LPCWSTR ImageName);
    static void WaitMicroSecond(ULONG ulMircoSecond);

};
extern "C" UCHAR * PsGetProcessImageFileName(PEPROCESS EProcess);
#endif