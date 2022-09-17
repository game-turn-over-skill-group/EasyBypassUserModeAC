#pragma warning (disable : 4100)
#include "proc.h"
#include "data.h"
#include "_global.h"
bool Process::IsProtectedProcess(HANDLE PID) {
	if (PID == data::CheatEnginePid)
		return true;
	else
		return false;
}

bool Process::IsBlackListProcess(HANDLE PID) {
	

    if (PID == data::MSPid || PID == data::BlackCipherPid)
		return true;
	else
		return false;
	
}

