#include "data.h"
#include "misc.h"
#include "message.h"
HANDLE data::CheatEnginePid = 0;
HANDLE data::MSPid = 0;
HANDLE data::BlackCipherPid = 0;

PVOID data::pThread = NULL;
volatile BOOLEAN data::bExit = FALSE;

VOID data::DataThread(PVOID pParam)
{
    UNREFERENCED_PARAMETER(pParam);
    while (bExit != TRUE) {
        Misc::WaitMicroSecond(500);
        
        if (data::CheatEnginePid != (HANDLE)Misc::FindProcess(L"cheatengine-x86_64.exe")) {
            data::CheatEnginePid = (HANDLE)Misc::FindProcess(L"cheatengine-x86_64.exe");
            DebugMessage("[+] CheatEnginePid = %d. \n", data::CheatEnginePid);
        }
        if (data::MSPid != (HANDLE)Misc::FindProcess(L"MapleStory.exe")) {
            data::MSPid = (HANDLE)Misc::FindProcess(L"MapleStory.exe");
            DebugMessage("[+] MSPid = %d. \n", data::MSPid);
        }
        if (data::BlackCipherPid != (HANDLE)Misc::FindProcess(L"BlackCipher64.aes")) {
            data::BlackCipherPid = (HANDLE)Misc::FindProcess(L"BlackCipher64.aes");
            DebugMessage("[+] BlackCipherPid = %d. \n", data::BlackCipherPid);
        }
       
    }

    DebugMessage("[+] Exit DataThread\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}
