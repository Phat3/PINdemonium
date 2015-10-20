#pragma once
#include "pin.H"
#include "WxorXHandler.h"
namespace W{
	#include "windows.h"
	#include <tlhelp32.h>
	#include <Psapi.h>	
}

typedef BOOL (*def_ScyllaDumpProcessA)(ADDRINT pid, const char * fileToDump, ADDRINT imagebase, ADDRINT entrypoint, const char * fileResult);



class InitFunctionCall
{
public:
	InitFunctionCall(void);
	~InitFunctionCall(void);
	UINT32 run(ADDRINT curEip,WriteInterval wi);
private:
	def_ScyllaDumpProcessA  ScyllaDumpProcessA ;
	W::HMODULE hScylla;
	BOOL GetFilePathFromPID(UINT32 dwProcessId, char **filename);
	ADDRINT GetExeModuleBase(UINT32 dwProcessId);

};

