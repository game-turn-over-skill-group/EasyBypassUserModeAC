#ifndef _WIN32K_H
#define _WIN32K_H

#include "_global.h"

class WIN32K
{
public:
    static NTSTATUS Initialize();
    static void Deinitialize();
    static int GetExportSsdtIndex(const char* ExportName);

private:
    static unsigned char* FileData;
    static ULONG FileSize;
};

#endif 