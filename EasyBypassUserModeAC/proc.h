#pragma once
#include<ntifs.h>
class Process
{
public:
	static bool IsBlackListProcess(HANDLE PID);
	static bool IsProtectedProcess(HANDLE PID);
};

