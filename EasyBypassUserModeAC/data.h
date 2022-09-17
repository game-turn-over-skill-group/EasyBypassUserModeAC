#pragma once
#include<ntifs.h>
namespace data
{
	extern HANDLE CheatEnginePid, MSPid, BlackCipherPid;
	extern PVOID pThread;
	extern volatile BOOLEAN bExit;

	VOID DataThread(PVOID pParam);
};

