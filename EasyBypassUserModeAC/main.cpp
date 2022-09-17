#include"message.h"
#include"log.h"
#include"ntdll.h"
#include"undocumented.h"
#include"threadhidefromdbg.h"
#include"hooks.h"
#include"misc.h"
#include"data.h"
#include"win32k.h"


static void UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
    data::bExit = TRUE;
    if (data::pThread != NULL) {
        KeWaitForSingleObject(data::pThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(data::pThread);
    }
    Hooks::Deinitialize();
    NTDLL::Deinitialize();
	DebugMessage("[+] UnloadDriver\n");
}


extern "C" NTSTATUS  DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    NTSTATUS status;
	UNREFERENCED_PARAMETER(pRegistryPath);
	pDriverObject->DriverUnload = UnloadDriver;
	DebugMessage("[+] DriverEntry\n");
 
    
    //read ntdll.dll from disk so we can use it for exports
    if (!NT_SUCCESS(NTDLL::Initialize()))
    {
        Log("[TITANHIDE] Ntdll::Initialize() failed...\r\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(WIN32K::Initialize()))
    {
        Log("[TITANHIDE] WIN32K::Initialize() failed...\r\n");
        return STATUS_UNSUCCESSFUL;
    }

    //initialize undocumented APIs
    if (!Undocumented::UndocumentedInit())
    {
        Log("[TITANHIDE] UndocumentedInit() failed...\r\n");
        return STATUS_UNSUCCESSFUL;
    }

    Log("[TITANHIDE] UndocumentedInit() was successful!\r\n");

    //find the offset of CrossThreadFlags in ETHREAD
    status = FindCrossThreadFlagsOffset(&CrossThreadFlagsOffset);
    if (!NT_SUCCESS(status))
    {
        Log("[TITANHIDE] FindCrossThreadFlagsOffset() failed: 0x%lX\r\n", status);
        return status;
    }
  
    HANDLE ThreadHandle;
    NTSTATUS status2 = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, (PHANDLE)-1, NULL, data::DataThread, NULL);

    // system thread
    //status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, data::DataThread, pDriverObject);

    if (status2 == STATUS_SUCCESS) {
        ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &data::pThread, NULL);
        ZwClose(ThreadHandle);
    }

 
    //initialize hooking 
          
    Log("[TITANHIDE] Hooks::Initialize() hooked %d functions\r\n", Hooks::Initialize());
  
   
	return STATUS_SUCCESS;
}

