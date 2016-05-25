#pragma once
#include "pin.H"
#include "WxorXHandler.h"
namespace W{
	#include "windows.h"
	#include <tlhelp32.h>
	#include <Psapi.h>	
}




typedef int (*def_ScyllaIatSearch)(ADDRINT dwProcessId, ADDRINT * iatStart, UINT32 * iatSize, ADDRINT searchStart, BOOL advancedSearch);
typedef int  (*def_ScyllaIatFixAutoA)(ADDRINT iatAddr, UINT32 iatSize, UINT32 dwProcessId, const char * dumpFile, const char * iatFixFile);
typedef BOOL (*def_ScyllaDumpProcessA)(ADDRINT pid, const char * fileToDump, ADDRINT imagebase, ADDRINT entrypoint, const char * fileResult);

	 


class InitFunctionCall
{
public:
	InitFunctionCall(void);
	~InitFunctionCall(void);
	UINT32 run(ADDRINT curEip);
private:
	def_ScyllaIatSearch ScyllaIatSearch;
	def_ScyllaIatFixAutoA  ScyllaIatFixAutoA;
	def_ScyllaDumpProcessA  ScyllaDumpProcessA;
	W::HMODULE hScylla;
	BOOL GetFilePathFromPID(UINT32 dwProcessId, char **filename);
	ADDRINT GetExeModuleBase(UINT32 dwProcessId);
	UINT32 getFileSize(FILE * fp);
	void DumpProcess(ADDRINT oep, char *outputFile);

};

