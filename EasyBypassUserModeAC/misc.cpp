#pragma warning (disable : 4047 4311 4302)
#include "misc.h"
#include "undocumented.h"

ULONG Misc::GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
    ULONG Pid = 0;
    PEPROCESS Process;
    if(NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID*)&Process, nullptr)))
    {
        Pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);
        ObDereferenceObject(Process);
    }
    return Pid;
}

ULONG Misc::GetProcessIDFromThreadHandle(HANDLE ThreadHandle)
{
    ULONG Pid = 0;
    PETHREAD Thread;
    if(NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, ExGetPreviousMode(), (PVOID*)&Thread, nullptr)))
    {
        Pid = (ULONG)(ULONG_PTR)PsGetProcessId(PsGetThreadProcess(Thread));
        ObDereferenceObject(Thread);
    }
    return Pid;
}

UCHAR* Misc::PsGetProcessImageFileName2(PEPROCESS EProcess) {
    return PsGetProcessImageFileName(EProcess);
}

UCHAR* Misc::GetProcessNameFromPid(HANDLE Pid) {
    PEPROCESS Process;
    if (PsLookupProcessByProcessId(Pid, &Process) == STATUS_INVALID_PARAMETER)
    {
        return NULL;
    }
    return PsGetProcessImageFileName(Process);
}


ULONG Misc::FindProcess(LPCWSTR ImageName)
{
	UNICODE_STRING ImageNameString;
	RtlInitUnicodeString(&ImageNameString, ImageName);

	ULONG buffer_size = 0;

	NTSTATUS status = Undocumented::ZwQuerySystemInformation(SystemProcessInformation, 0, buffer_size, &buffer_size);


	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] failed to allocate\n");
		return NULL;
	}
	buffer_size = 2 * buffer_size;
	PVOID buffer = ExAllocatePool(NonPagedPool, buffer_size);

	status = Undocumented::ZwQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, &buffer_size);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] failed to allocate2 : %X  \n", status);
		ExFreePool(buffer);
		return NULL;
	}

	PSYSTEM_PROCESS_INFORMATION current_process = (PSYSTEM_PROCESS_INFORMATION)(buffer);

	while (1)
	{
		current_process = (PSYSTEM_PROCESS_INFORMATION)(((unsigned char*)current_process) + current_process->NextEntryOffset);
		if (RtlEqualUnicodeString(&current_process->ImageName, &ImageNameString, TRUE))
		{
			HANDLE return_value = current_process->UniqueProcessId;
			ExFreePool(buffer);
			return (ULONG)(return_value);
		}
		if (current_process->NextEntryOffset == 0)
			break;
	}
	ExFreePool(buffer);

	return NULL;
}



VOID Misc::WaitMicroSecond(ULONG ulMircoSecond)
{
	LARGE_INTEGER timeout = RtlConvertLongToLargeInteger(-10 * ulMircoSecond);
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
}