#pragma warning (disable :4505 4311 4302 4189 4706)
#include "hooks.h"
#include "undocumented.h"
#include "ssdt.h"
#include "misc.h"
#include "log.h"
#include "data.h"
#include "message.h"
#include "proc.h"
#include "ssdtshadow.h"
#include <intrin.h>

static HOOK hNtQueryInformationProcess = 0;
static HOOK hNtQueryInformationThread = 0;
static HOOK hNtQueryObject = 0;
static HOOK hNtQuerySystemInformation = 0;
static HOOK hNtClose = 0;
static HOOK hNtDuplicateObject = 0;
static HOOK hNtSetInformationThread = 0;
static HOOK hNtGetContextThread = 0;
static HOOK hNtSetContextThread = 0;
static HOOK hNtSystemDebugControl = 0;
static HOOK hNtCreateThreadEx = 0;
static KMUTEX gDebugPortMutex;
static HOOK hNtOpenProcess = 0;
static HOOK hNtReadVirtualMemory = 0;
static HOOK hNtQueryVirtualMemory = 0;
static HOOK hNtCreateFile = 0;
static HOOK hNtUserQueryWindow = 0;
static HOOK hNtUserFindWindowEx = 0;
static HOOK hNtUserBuildHwndList = 0;
static HOOK hNtUserGetForegroundWindow = 0;
//https://forum.tuts4you.com/topic/40011-debugme-vmprotect-312-build-886-anti-debug-method-improved/#comment-192824
//https://github.com/x64dbg/ScyllaHide/issues/47
//https://github.com/mrexodia/TitanHide/issues/27
#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        TempReturnLength = *ReturnLength

#define RESTORE_RETURNLENGTH() \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        (*ReturnLength) = TempReturnLength

#define OBJ_PROTECT_CLOSE 0x00000001L

static NTSTATUS NTAPI HookNtQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
      
    HANDLE pid = PsGetCurrentProcessId();
    ULONG targetPid = Misc::GetProcessIDFromThreadHandle(ThreadHandle);

#ifdef _WIN64 // ThreadWow64Context returns STATUS_INVALID_INFO_CLASS on x86, and STATUS_INVALID_PARAMETER if PreviousMode is kernel
    if(ThreadInformationClass == ThreadWow64Context &&
            ThreadInformation != nullptr &&
            ThreadInformationLength == sizeof(WOW64_CONTEXT) &&
            ExGetPreviousMode() != KernelMode &&
            Process::IsBlackListProcess(pid) &&
            Process::IsBlackListProcess((HANDLE)targetPid))
    {
        PWOW64_CONTEXT Wow64Context = (PWOW64_CONTEXT)ThreadInformation;
        ULONG OriginalContextFlags = 0;
        bool DebugRegistersRequested = false;

        Log("[TITANHIDE] NtGetContextThread by %d\r\n", pid);

        __try
        {
            ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
            OriginalContextFlags = Wow64Context->ContextFlags;
            Wow64Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
            DebugRegistersRequested = Wow64Context->ContextFlags != OriginalContextFlags;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            NOTHING;
        }

        const NTSTATUS Status = Undocumented::NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

        __try
        {
            ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
            Wow64Context->ContextFlags = OriginalContextFlags;

            // If debug registers were requested, zero user input
            if(DebugRegistersRequested)
            {
                Wow64Context->Dr0 = 0;
                Wow64Context->Dr1 = 0;
                Wow64Context->Dr2 = 0;
                Wow64Context->Dr3 = 0;
                Wow64Context->Dr6 = 0;
                Wow64Context->Dr7 = 0;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            NOTHING;
        }

        return Status;
    }
#endif

    // Call the original function now, since querying ThreadHideFromDebugger may fail with STATUS_INVALID_INFO_CLASS (if we are on XP/2003)
    NTSTATUS Status = Undocumented::NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

    if(NT_SUCCESS(Status) && ThreadInformationClass == ThreadHideFromDebugger)
    {
        if(Process::IsBlackListProcess(pid) && Process::IsBlackListProcess((HANDLE)targetPid))
        {
            Log("[TITANHIDE] NtQueryInformationThread(ThreadHideFromDebugger) by %d\r\n", pid);

            __try
            {
                BACKUP_RETURNLENGTH();

                // Since they're asking, assume they're expecting "yes"
                *(BOOLEAN*)ThreadInformation = TRUE;

                RESTORE_RETURNLENGTH();
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = GetExceptionCode();
            }
        }
    }

    return Status;
    
    
    
}

static NTSTATUS NTAPI HookNtSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength)
{
    HANDLE pid = PsGetCurrentProcessId();

    //Bug found by Aguila, thanks!
    if(ThreadInformationClass == ThreadHideFromDebugger && !ThreadInformationLength)
    {
        if(Process::IsBlackListProcess(pid))
        {
            Log("[TITANHIDE] NtSetInformationThread(ThreadHideFromDebugger) by %d\r\n", pid);
            PETHREAD Thread;
            NTSTATUS status = ObReferenceObjectByHandle(ThreadHandle,
                              THREAD_SET_INFORMATION,
                              *PsThreadType,
                              ExGetPreviousMode(),
                              (PVOID*)&Thread,
                              NULL);
            if(NT_SUCCESS(status))
                ObDereferenceObject(Thread);
            return status;
        }
    }
    // ThreadWow64Context returns STATUS_INVALID_INFO_CLASS on x86, and STATUS_INVALID_PARAMETER if PreviousMode is kernel
#ifdef _WIN64
    else if(ThreadInformationClass == ThreadWow64Context &&
            ThreadInformation != nullptr &&
            ThreadInformationLength == sizeof(WOW64_CONTEXT) &&
            ExGetPreviousMode() != KernelMode &&
            Process::IsBlackListProcess(pid))
    {
        PWOW64_CONTEXT Wow64Context = (PWOW64_CONTEXT)ThreadInformation;
        ULONG OriginalContextFlags = 0;

        Log("[TITANHIDE] NtSetContextThread by %d\r\n", pid);

        __try
        {
            ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
            OriginalContextFlags = Wow64Context->ContextFlags;
            Wow64Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            NOTHING;
        }

        const NTSTATUS Status = Undocumented::NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

        __try
        {
            ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
            Wow64Context->ContextFlags = OriginalContextFlags;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            NOTHING;
        }

        return Status;
    }
#endif

    return Undocumented::NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

static NTSTATUS NTAPI HookNtClose(
    IN HANDLE Handle)
{
    HANDLE pid = PsGetCurrentProcessId();
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    if(Process::IsBlackListProcess(pid))
    {
        KeWaitForSingleObject(&gDebugPortMutex, Executive, KernelMode, FALSE, nullptr);

        // Check if this is a valid handle without raising exceptionss
        BOOLEAN AuditOnClose;
        NTSTATUS ObStatus = ObQueryObjectAuditingByHandle(Handle, &AuditOnClose);

        NTSTATUS Status;
        if(ObStatus != STATUS_INVALID_HANDLE)  // Don't change the return path for any status except this one
        {
            BOOLEAN BeingDebugged = PsGetProcessDebugPort(PsGetCurrentProcess()) != nullptr;
            OBJECT_HANDLE_INFORMATION HandleInfo = { 0 };

            if(BeingDebugged)
            {
                // Get handle info so we can check if the handle has the ProtectFromClose bit set
                PVOID Object = nullptr;
                ObStatus = ObReferenceObjectByHandle(Handle,
                                                     0,
                                                     nullptr,
                                                     PreviousMode,
                                                     &Object,
                                                     &HandleInfo);
                if(Object != nullptr)
                    ObDereferenceObject(Object);
            }

            if(BeingDebugged && NT_SUCCESS(ObStatus) &&
                    (HandleInfo.HandleAttributes & OBJ_PROTECT_CLOSE))
            {
                // Return STATUS_HANDLE_NOT_CLOSABLE instead of raising an exception
                Log("[TITANHIDE] NtClose(0x%p) (protected handle) by %d\r\n", Handle, pid);
                Status = STATUS_HANDLE_NOT_CLOSABLE;
            }
            else
            {
                Status = ObCloseHandle(Handle, PreviousMode);
            }
        }
        else
        {
            Log("[TITANHIDE] NtClose(0x%p) by %d\r\n", Handle, pid);
            Status = STATUS_INVALID_HANDLE;
        }

        KeReleaseMutex(&gDebugPortMutex, FALSE);

        return Status;
    }
    return ObCloseHandle(Handle, PreviousMode);
}

static NTSTATUS NTAPI HookNtDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN ULONG HandleAttributes,
    IN ULONG Options)
{
    HANDLE pid = PsGetCurrentProcessId();
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    if (Process::IsBlackListProcess(pid))
    {
        BOOLEAN BeingDebugged = PsGetProcessDebugPort(PsGetCurrentProcess()) != nullptr;
        if (BeingDebugged && (Options & DUPLICATE_CLOSE_SOURCE))
        {
            // Get handle info so we can check if the handle has the ProtectFromClose bit set
            PVOID Object = nullptr;
            OBJECT_HANDLE_INFORMATION HandleInfo = { 0 };
            NTSTATUS Status = ObReferenceObjectByHandle(SourceHandle,
                0,
                nullptr,
                PreviousMode,
                &Object,
                &HandleInfo);

            if (NT_SUCCESS(Status))
            {
                if (Object != nullptr)
                    ObDereferenceObject(Object);

                if (HandleInfo.HandleAttributes & OBJ_PROTECT_CLOSE)
                {
                    // Prevent a user mode exception from happening when ObDuplicateObject calls NtClose on the source handle.
                    // Why doesn't our NtClose hook catch this? Because the kernel uses its own RVAs instead of going through the SSDT
                    Options &= ~DUPLICATE_CLOSE_SOURCE;
                }
            }
        }
    }

    return Undocumented::NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);

}

static NTSTATUS NTAPI HookNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    
    /*
    PVOID* StackFrame=(PVOID*)_AddressOfReturnAddress();
    DWORD64 test = (DWORD64)StackFrame + 368;
    DWORD64 test2 = *(DWORD64*)(test);
    DebugMessage("[+] %llx %llx %llx \n", StackFrame, test, test2);
    
    */

   
    NTSTATUS status = Undocumented::NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength,ReturnLength);  
    if (!Process::IsBlackListProcess(PsGetCurrentProcessId()))
        return status;

    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    if (STATUS_SUCCESS == status) {
        if (SystemInformationClass == SystemProcessInformation ||
            SystemInformationClass == SystemSessionProcessInformation ||
            SystemInformationClass == SystemExtendedProcessInformation)
        {
         
            SYSTEM_PROCESS_INFORMATION* pCurrent = NULL;
            SYSTEM_PROCESS_INFORMATION* pNext = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
            do {
                pCurrent = pNext;
                pNext = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
                if (Process::IsProtectedProcess(pNext->UniqueProcessId))
                {
                    DebugMessage("[+] NtQuerySystemInformation from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));
                    if (!pNext->NextEntryOffset)
                    {
                        pCurrent->NextEntryOffset = 0;
                    }
                    else
                    {
                        pCurrent->NextEntryOffset += pNext->NextEntryOffset;
                    }
                    pNext = pCurrent;
                }
            } while (pCurrent->NextEntryOffset != 0);
            
        }
        else if (SystemInformationClass == SystemHandleInformation)
        {       
            const auto pHandle = PSYSTEM_HANDLE_INFORMATION(SystemInformation);
            const auto pEntry = &pHandle->Information[0];
            for (unsigned i = 0; i < pHandle->NumberOfHandles; ++i)
            {
                if (Process::IsProtectedProcess(ULongToHandle(pEntry[i].ProcessId)))
                {
                    const auto next_entry = i + 1;
                    if (next_entry < pHandle->NumberOfHandles)
                        memcpy(&pEntry[i], &pEntry[next_entry], sizeof(SYSTEM_HANDLE));
                    else
                    {
                        memset(&pEntry[i], 0, sizeof(SYSTEM_HANDLE));
                        pHandle->NumberOfHandles--;
                    }
                }
            }
        }      
        else if (SystemInformationClass == SystemExtendedHandleInformation)
        {        
            const auto pHandle = PSYSTEM_HANDLE_INFORMATION_EX(SystemInformation);
            const auto pEntry = &pHandle->Information[0];
            for (unsigned i = 0; i < pHandle->NumberOfHandles; ++i)
            {
                if (Process::IsProtectedProcess(ULongToHandle(pEntry[i].ProcessId)))
                {
                    const auto next_entry = i + 1;

                    if (next_entry < pHandle->NumberOfHandles)
                        memcpy(&pEntry[i], &pEntry[next_entry], sizeof(SYSTEM_HANDLE));
                    else
                    {
                        memset(&pEntry[i], 0, sizeof(SYSTEM_HANDLE));
                        pHandle->NumberOfHandles--;
                    }
                }
            }           
        } 
        else if (SystemInformationClass == SystemKernelDebuggerInformation)
        {            
            Log("[TITANHIDE] SystemKernelDebuggerInformation by %d\r\n", PsGetCurrentProcessId());
            typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
            {
                BOOLEAN DebuggerEnabled;
                BOOLEAN DebuggerNotPresent;
            } SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
            SYSTEM_KERNEL_DEBUGGER_INFORMATION* DebuggerInfo = (SYSTEM_KERNEL_DEBUGGER_INFORMATION*)SystemInformation;
            __try
            {
                BACKUP_RETURNLENGTH();

                DebuggerInfo->DebuggerEnabled = false;
                DebuggerInfo->DebuggerNotPresent = true;

                RESTORE_RETURNLENGTH();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }           
        }
    }
    return status;
      
    
}

static NTSTATUS NTAPI HookNtQueryObject(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
        
    NTSTATUS ret = Undocumented::NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) && ObjectInformation)
    {
        HANDLE pid = PsGetCurrentProcessId();
        UNICODE_STRING DebugObject;
        RtlInitUnicodeString(&DebugObject, L"DebugObject");
        if(ObjectInformationClass == ObjectTypeInformation && Process::IsBlackListProcess(pid))
        {
            __try
            {
                BACKUP_RETURNLENGTH();

                OBJECT_TYPE_INFORMATION* type = (OBJECT_TYPE_INFORMATION*)ObjectInformation;
                ProbeForRead(type->TypeName.Buffer, 1, 1);
                if(RtlEqualUnicodeString(&type->TypeName, &DebugObject, FALSE)) //DebugObject
                {
                    Log("[TITANHIDE] DebugObject by %d\r\n", pid);
                    type->TotalNumberOfObjects = 0;
                    type->TotalNumberOfHandles = 0;
                }

                RESTORE_RETURNLENGTH();
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                ret = GetExceptionCode();
            }
        }
        else if(ObjectInformationClass == ObjectTypesInformation && Process::IsBlackListProcess(pid))
        {
            //NCC Group Security Advisory
            __try
            {
                BACKUP_RETURNLENGTH();

                OBJECT_ALL_INFORMATION* pObjectAllInfo = (OBJECT_ALL_INFORMATION*)ObjectInformation;
                unsigned char* pObjInfoLocation = (unsigned char*)pObjectAllInfo->ObjectTypeInformation;
                unsigned int TotalObjects = pObjectAllInfo->NumberOfObjects;
                for(unsigned int i = 0; i < TotalObjects; i++)
                {
                    OBJECT_TYPE_INFORMATION* pObjectTypeInfo = (OBJECT_TYPE_INFORMATION*)pObjInfoLocation;
                    ProbeForRead(pObjectTypeInfo, 1, 1);
                    ProbeForRead(pObjectTypeInfo->TypeName.Buffer, 1, 1);
                    if(RtlEqualUnicodeString(&pObjectTypeInfo->TypeName, &DebugObject, FALSE)) //DebugObject
                    {
                        Log("[TITANHIDE] DebugObject by %d\r\n", pid);
                        pObjectTypeInfo->TotalNumberOfObjects = 0;
                        //Bug found by Aguila, thanks!
                        pObjectTypeInfo->TotalNumberOfHandles = 0;
                    }
                    pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;
                    pObjInfoLocation += pObjectTypeInfo->TypeName.MaximumLength;
                    ULONG_PTR tmp = ((ULONG_PTR)pObjInfoLocation) & -(LONG_PTR)sizeof(void*);
                    if((ULONG_PTR)tmp != (ULONG_PTR)pObjInfoLocation)
                        tmp += sizeof(void*);
                    pObjInfoLocation = ((unsigned char*)tmp);
                }

                RESTORE_RETURNLENGTH();
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                ret = GetExceptionCode();
            }
        }
    }
    return ret;
    
    
}

static NTSTATUS NTAPI HookNtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength)
{
    HANDLE Pid;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    Pid = PsGetProcessId(CurrentProcess);
    if (Process::IsBlackListProcess(Pid)) {
        Pid = (HANDLE)Misc::GetProcessIDFromProcessHandle(ProcessHandle);
        if (Process::IsProtectedProcess(Pid)) {
            DebugMessage("[+] NtQueryInformationProces from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));            
            ObCloseHandle(ProcessHandle, ExGetPreviousMode());
            return STATUS_ACCESS_DENIED;
        }
    }   
     
    Pid = (HANDLE)Misc::GetProcessIDFromProcessHandle(ProcessHandle);

    // Handle ProcessDebugObjectHandle early
    if(ProcessInformationClass == ProcessDebugObjectHandle &&
            ProcessInformation != nullptr &&
            ProcessInformationLength == sizeof(HANDLE) &&
            Process::IsBlackListProcess(Pid))
    {
        PEPROCESS Process;
        NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle,
                          PROCESS_QUERY_INFORMATION,
                          *PsProcessType,
                          ExGetPreviousMode(),
                          (PVOID*)&Process,
                          nullptr);
        if(!NT_SUCCESS(Status))
            return Status;

        // (The kernel calls DbgkOpenProcessDebugPort here)

        ObDereferenceObject(Process);

        __try
        {
            *(PHANDLE)ProcessInformation = nullptr;
            if(ReturnLength != nullptr)
                *ReturnLength = sizeof(HANDLE);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
        return STATUS_PORT_NOT_SET;
    }

    NTSTATUS ret = Undocumented::NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) &&
            ProcessInformation &&
            ProcessInformationClass != ProcessBasicInformation) //prevent stack overflow
    {
        if(ProcessInformationClass == ProcessDebugFlags)
        {
            if(Process::IsBlackListProcess(Pid))
            {
                Log("[TITANHIDE] ProcessDebugFlags by %d\r\n", Pid);
                __try
                {
                    BACKUP_RETURNLENGTH();

                    *(unsigned int*)ProcessInformation = TRUE;

                    RESTORE_RETURNLENGTH();
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    ret = GetExceptionCode();
                }
            }
        }
        else if(ProcessInformationClass == ProcessDebugPort)
        {
            if(Process::IsBlackListProcess(Pid))
            {
                Log("[TITANHIDE] ProcessDebugPort by %d\r\n", Pid);
                __try
                {
                    BACKUP_RETURNLENGTH();

                    *(ULONG_PTR*)ProcessInformation = 0;

                    RESTORE_RETURNLENGTH();
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    ret = GetExceptionCode();
                }
            }
        }
    }
    return ret;
    
}

static NTSTATUS NTAPI HookNtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT Context)
{

    
    HANDLE pid = PsGetCurrentProcessId();
    ULONG targetPid = Misc::GetProcessIDFromThreadHandle(ThreadHandle);
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    bool IsHidden = PreviousMode != KernelMode &&
                    Process::IsBlackListProcess((HANDLE)pid) &&
                    Process::IsBlackListProcess((HANDLE)targetPid);
    ULONG OriginalContextFlags = 0;
    bool DebugRegistersRequested = false;
    if(IsHidden)
    {
        Log("[TITANHIDE] NtGetContextThread by %d\r\n", pid);
        __try
        {
            ProbeForWrite(&Context->ContextFlags, sizeof(ULONG), 1);
            OriginalContextFlags = Context->ContextFlags;
            Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
            DebugRegistersRequested = Context->ContextFlags != OriginalContextFlags;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            IsHidden = false;
        }
    }
    NTSTATUS ret = Undocumented::NtGetContextThread(ThreadHandle, Context);
    if(IsHidden)
    {
        __try
        {
            ProbeForWrite(&Context->ContextFlags, sizeof(ULONG), 1);
            Context->ContextFlags = OriginalContextFlags;

            // If debug registers were requested, zero user input
            if(DebugRegistersRequested)
            {
                Context->Dr0 = 0;
                Context->Dr1 = 0;
                Context->Dr2 = 0;
                Context->Dr3 = 0;
                Context->Dr6 = 0;
                Context->Dr7 = 0;
#ifdef _WIN64
                Context->LastBranchToRip = 0;
                Context->LastBranchFromRip = 0;
                Context->LastExceptionToRip = 0;
                Context->LastExceptionFromRip = 0;
#endif
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
    return ret;
    
   
}

static NTSTATUS NTAPI HookNtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context)
{
    HANDLE pid = PsGetCurrentProcessId();
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    bool IsHidden = PreviousMode != KernelMode && Process::IsBlackListProcess(pid);
    ULONG OriginalContextFlags = 0;
    if(IsHidden)
    {
        //http://lifeinhex.com/dont-touch-this-writing-good-drivers-is-really-hard
        //http://lifeinhex.com/when-software-is-good-enough
        Log("[TITANHIDE] NtSetContextThread by %d\r\n", pid);
        __try
        {
            ProbeForWrite(&Context->ContextFlags, sizeof(ULONG), 1);
            OriginalContextFlags = Context->ContextFlags;
            Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            IsHidden = false;
        }
    }
    NTSTATUS ret = Undocumented::NtSetContextThread(ThreadHandle, Context);
    if(IsHidden)
    {
        __try
        {
            ProbeForWrite(&Context->ContextFlags, sizeof(ULONG), 1);
            Context->ContextFlags = OriginalContextFlags;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
    return ret;
}

static NTSTATUS NTAPI HookNtSystemDebugControl(
    IN SYSDBG_COMMAND Command,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnLength)
{
    HANDLE pid = PsGetCurrentProcessId();
    if(Command != SysDbgGetTriageDump && Command != SysDbgGetLiveKernelDump && Process::IsBlackListProcess(pid))
    {
        Log("[TITANHIDE] NtSystemDebugControl by %d\r\n", pid);
        return STATUS_DEBUGGER_INACTIVE;
    }
    return Undocumented::NtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
}

static NTSTATUS NTAPI HookNtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PUSER_THREAD_START_ROUTINE StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
    HANDLE pid = PsGetCurrentProcessId();
    if(Process::IsBlackListProcess(pid))
    {
        if((CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER) != 0)
        {
            CreateFlags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
            Log("[TITANHIDE] NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER by %u\r\n", pid);
        }
    }
    return Undocumented::NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

static NTSTATUS NTAPI HookNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId) 
{   
    HANDLE Pid;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    Pid = PsGetProcessId(CurrentProcess);
    if (Process::IsBlackListProcess(Pid)) {
        if (Process::IsProtectedProcess(ClientId->UniqueProcess)) {
            DebugMessage("[+] NtOpenProcess from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));
            return STATUS_ACCESS_DENIED;
        }
    }
    return Undocumented::NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

static NTSTATUS NTAPI HookNtReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN ULONG BufferLength,
    OUT PULONG ReturnLength OPTIONAL) 
{
    HANDLE Pid;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    Pid = PsGetProcessId(CurrentProcess);
    if (Process::IsBlackListProcess(Pid)){
        Pid = (HANDLE)Misc::GetProcessIDFromProcessHandle(ProcessHandle);
        if (Process::IsProtectedProcess(Pid)) {
            DebugMessage("[+] NtReadVirtualMemory from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));
            ObCloseHandle(ProcessHandle, ExGetPreviousMode());
            return STATUS_ACCESS_DENIED;
        }
    }
    Pid = PsGetProcessId(CurrentProcess);
    if (Pid == data::BlackCipherPid) {
        Pid = (HANDLE)Misc::GetProcessIDFromProcessHandle(ProcessHandle);
        if (Pid == data::MSPid) {
            /*
             DWORD64 StackFrame = (DWORD64)_AddressOfReturnAddress();
            DWORD64 test = *(DWORD64*)(StackFrame + 480);
            DebugMessage("[+] HookNtReadVirtualMemory %llx %llx  \n", StackFrame, test);
            */
          

            //DebugMessage("[+]BaseAddress = %llx, BufferLength = %x \n", BaseAddress, BufferLength);
            if ((DWORD64)BaseAddress == 0x140001000) {
                static int count = 0;
                static PVOID MS_dump;
                static ULONG length;
                if (count > 0) {
                    NTSTATUS status = Undocumented::NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
                    RtlCopyMemory(Buffer, MS_dump, length);
                    DebugMessage("[+] BaseAddress = %llx, BufferLength = %x \n", BaseAddress, BufferLength);
                    DebugMessage("[+] Memory has been replaced\n");
                    return status;
                }
                else {
                    count++;
                    MS_dump = ExAllocatePool(NonPagedPool, BufferLength);
                    length = BufferLength;
                    NTSTATUS status = Undocumented::NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
                    RtlCopyMemory(MS_dump, Buffer, BufferLength);
                    DebugMessage("[+] BaseAddress = %llx, BufferLength = %x \n", BaseAddress, BufferLength);
                    DebugMessage("[+] Memory has been dumped\n");
                    return status;
                }
            }
        }
    }
    return Undocumented::NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
}

static NTSTATUS NTAPI HookNtQueryVirtualMemory(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength)
{
    HANDLE Pid;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    Pid = PsGetProcessId(CurrentProcess);

    if (Process::IsBlackListProcess(Pid)) {
        Pid = (HANDLE)Misc::GetProcessIDFromProcessHandle(ProcessHandle);
        if (Process::IsProtectedProcess(Pid)) {
            DebugMessage("[+] NtQueryVirtualMemory from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));
            

            return STATUS_ACCESS_DENIED;
        }
    }
    
    return  Undocumented::NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

}


static NTSTATUS NTAPI HookNtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength)
{
    HANDLE Pid;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    Pid = PsGetProcessId(CurrentProcess);
    if (Process::IsBlackListProcess(Pid)) {
        wchar_t* FileName = ObjectAttributes->ObjectName->Buffer;
        if (FileName) {
            if (wcsstr(FileName, L"HackTools")) {
                DebugMessage("[+] NtCreateFile from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));
                return STATUS_ACCESS_DENIED;
            }
        }
        
    }
    return Undocumented::NtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength
    );
}



bool IsWindowBad(HWND hWnd) 
{
    HANDLE Pid = Undocumented::NtUserQueryWindow(hWnd, 0);
    if (Process::IsProtectedProcess(Pid)) {
       
        return true;
    }
    return false;
}


static HANDLE NTAPI HookNtUserQueryWindow(
    HWND WindowHandle,
    HANDLE TypeInformatio) 
{
    HANDLE Pid;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    Pid = PsGetProcessId(CurrentProcess);
    if (Process::IsBlackListProcess(Pid)) {       
        if (IsWindowBad(WindowHandle)) {
            DebugMessage("[+] NtUserQueryWindow from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));
            return 0;
        }            
    }
    return Undocumented::NtUserQueryWindow(WindowHandle, TypeInformatio);
}




static NTSTATUS NTAPI HookNtUserBuildHwndList(
    HDESK hDesktop, 
    HWND hwndParent, 
    BOOL bChildren,
    BOOL  RemoveImmersive,
    ULONG dwThreadId, 
    ULONG lParam, 
    HWND* pWnd, 
    PULONG pBufSize)
{
    NTSTATUS ntStat = Undocumented::NtUserBuildHwndList(hDesktop, hwndParent, bChildren, RemoveImmersive, dwThreadId, lParam, pWnd, pBufSize);

    HANDLE Pid;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    Pid = PsGetProcessId(CurrentProcess);
    if (!Process::IsBlackListProcess(Pid)) {
        return ntStat;
    }
    
    if (NT_SUCCESS(ntStat) && pWnd != nullptr && pBufSize != nullptr)
    {      
        DebugMessage("[+] NtUserBuildHwndList from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));
        HWND* phwndFirst = pWnd;
        PULONG pcHwndNeeded = pBufSize;
        for (UINT i = 0; i < *pcHwndNeeded; i++)
        {
            if (phwndFirst[i] != nullptr && IsWindowBad(phwndFirst[i]))
            {      
                if (i == 0)
                {
                    // Find the first HWND that belongs to a different process (i + 1, i + 2... may still be ours)
                    for (UINT j = i + 1; j < *pcHwndNeeded; j++)
                    {
                        if (phwndFirst[j] != nullptr && !IsWindowBad(phwndFirst[j]))
                        {
                            phwndFirst[i] = phwndFirst[j];
                            break;
                        }
                    }
                }
                else
                {
                    phwndFirst[i] = phwndFirst[i - 1]; //just override with previous
                }
            }
        }
    }
   

    return ntStat;
}




static HWND NTAPI HookNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType) 
{
    HWND res = Undocumented::NtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
    HANDLE Pid;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    Pid = PsGetProcessId(CurrentProcess);
    if (Process::IsBlackListProcess(Pid)) {    
        if (IsWindowBad(res)) {
            DebugMessage("[+] NtUserFindWindowEx from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));
            return 0;
        }  
    }
    return res;
}
static HWND NTAPI HookNtUserGetForegroundWindow() 
{
    static HWND LastForeWnd=0;
    HWND res = Undocumented::NtUserGetForegroundWindow();
    HANDLE Pid;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    Pid = PsGetProcessId(CurrentProcess);
    if (Process::IsBlackListProcess(Pid)) {     
        if (IsWindowBad(res)) {
            DebugMessage("[+] NtUserGetForegroundWindow from %s\n", Misc::PsGetProcessImageFileName2(CurrentProcess));
            return LastForeWnd;
        }
        else {
            LastForeWnd = res;
        }      
    }
    return res;
}

int Hooks::Initialize()
{
    KeInitializeMutex(&gDebugPortMutex, 0);
    int hook_count = 0;  
    
    hNtQueryVirtualMemory = SSDT::Hook("NtQueryVirtualMemory", (void*)HookNtQueryVirtualMemory);
    if (hNtQueryVirtualMemory)
        hook_count++;
    hNtOpenProcess = SSDT::Hook("NtOpenProcess", (void*)HookNtOpenProcess);
    if (hNtOpenProcess)
        hook_count++;
    hNtQueryInformationProcess = SSDT::Hook("NtQueryInformationProcess", (void*)HookNtQueryInformationProcess);
    if (hNtQueryInformationProcess)
        hook_count++;
    hNtReadVirtualMemory = SSDT::Hook("NtReadVirtualMemory", (void*)HookNtReadVirtualMemory);
    if (hNtReadVirtualMemory)
        hook_count++;
    hNtCreateFile = SSDT::Hook("NtCreateFile", (void*)HookNtCreateFile);
    if (hNtCreateFile)
        hook_count++;
    hNtQuerySystemInformation = SSDT::Hook("NtQuerySystemInformation", (void*)HookNtQuerySystemInformation);
    if (hNtQuerySystemInformation)
        hook_count++;
   

    PEPROCESS Process;
    HANDLE winlogonPID = (HANDLE)Misc::FindProcess(L"winlogon.exe");
    if (winlogonPID) {
        if (NT_SUCCESS(PsLookupProcessByProcessId(winlogonPID, &Process))) {
            KAPC_STATE oldApc;
            KeStackAttachProcess(Process, &oldApc);
            hNtUserBuildHwndList = SSDTSHADOW::Hook("NtUserBuildHwndList", (void*)HookNtUserBuildHwndList);
            if (hNtUserBuildHwndList)
                hook_count++;                 
            hNtUserFindWindowEx = SSDTSHADOW::Hook("NtUserFindWindowEx", (void*)HookNtUserFindWindowEx);
            if (hNtUserFindWindowEx)
                hook_count++;
            hNtUserQueryWindow = SSDTSHADOW::Hook("NtUserQueryWindow", (void*)HookNtUserQueryWindow);
            if (hNtUserQueryWindow)
                hook_count++;            
            hNtUserGetForegroundWindow = SSDTSHADOW::Hook("NtUserGetForegroundWindow", (void*)HookNtUserGetForegroundWindow);
            if (hNtUserGetForegroundWindow)
                hook_count++;      
            KeUnstackDetachProcess(&oldApc);
        }
    }
    
   
   hNtQueryInformationThread = SSDT::Hook("NtQueryInformationThread", (void*)HookNtQueryInformationThread);
    if (hNtQueryInformationThread)
        hook_count++;
     hNtDuplicateObject = SSDT::Hook("NtDuplicateObject", (void*)HookNtDuplicateObject);
    if (hNtDuplicateObject)
        hook_count++;
     hNtGetContextThread = SSDT::Hook("NtGetContextThread", (void*)HookNtGetContextThread);
    if (hNtGetContextThread)
        hook_count++;
        hNtClose = SSDT::Hook("NtClose", (void*)HookNtClose);
    if (hNtClose)
        hook_count++;
      hNtQueryObject = SSDT::Hook("NtQueryObject", (void*)HookNtQueryObject);
    if (hNtQueryObject)
        hook_count++; 
    hNtSetInformationThread = SSDT::Hook("NtSetInformationThread", (void*)HookNtSetInformationThread);
    if(hNtSetInformationThread)
        hook_count++;
    hNtSystemDebugControl = SSDT::Hook("NtSystemDebugControl", (void*)HookNtSystemDebugControl);
    if (hNtSystemDebugControl)
        hook_count++;
    
    if ((NtBuildNumber & 0xFFFF) >= 6000)
    {
        hNtCreateThreadEx = SSDT::Hook("NtCreateThreadEx", (void*)HookNtCreateThreadEx);
        if (hNtCreateThreadEx)
            hook_count++;
    }
    
    hNtSetContextThread = SSDT::Hook("NtSetContextThread", (void*)HookNtSetContextThread);
    if(hNtSetContextThread)
        hook_count++;
   
       
    return hook_count;
}

void Hooks::Deinitialize()
{
    SSDT::Unhook(hNtQueryInformationProcess, true);
    SSDT::Unhook(hNtQueryInformationThread, true);
    SSDT::Unhook(hNtQueryObject, true);
    SSDT::Unhook(hNtQuerySystemInformation, true);
    SSDT::Unhook(hNtSetInformationThread, true);
    SSDT::Unhook(hNtClose, true);
    SSDT::Unhook(hNtDuplicateObject, true);
    SSDT::Unhook(hNtGetContextThread, true);
    SSDT::Unhook(hNtSetContextThread, true);
    SSDT::Unhook(hNtSystemDebugControl, true);
    if((NtBuildNumber & 0xFFFF) >= 6000)
    {
        SSDT::Unhook(hNtCreateThreadEx, true);
    }
    SSDT::Unhook(hNtOpenProcess, true);
    SSDT::Unhook(hNtReadVirtualMemory, true);
    SSDT::Unhook(hNtQueryVirtualMemory, true);
    SSDT::Unhook(hNtCreateFile, true);

    PEPROCESS Process;
    HANDLE winlogonPID = (HANDLE)Misc::FindProcess(L"winlogon.exe");
    if (winlogonPID) {
        if (NT_SUCCESS(PsLookupProcessByProcessId(winlogonPID, &Process))) {
            KAPC_STATE oldApc;
            KeStackAttachProcess(Process, &oldApc);        
            SSDTSHADOW::Unhook(hNtUserQueryWindow, true);
            SSDTSHADOW::Unhook(hNtUserFindWindowEx, true);
            SSDTSHADOW::Unhook(hNtUserBuildHwndList, true);
            SSDTSHADOW::Unhook(hNtUserGetForegroundWindow, true);
            KeUnstackDetachProcess(&oldApc);
        }
    }
}
