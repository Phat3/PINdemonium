#pragma once
#include "pin.H"
#include "WxorXHandler.h"
#include "ProcInfo.h"
#include <sstream>
namespace W{
	#include "windows.h"
	#include <tlhelp32.h>
	#include <Psapi.h>	
}





class InitFunctionCall
{
public:
	InitFunctionCall(void);
	~InitFunctionCall(void);
	UINT32 run(ADDRINT curEip,WriteInterval wi);
private:
	UINT32 getFileSize(FILE * fp);
	BOOL launchIdaScript(string idaw,string idaPythonScript,string  idaPythonInput,string idaPythonOutput,string dumpFileName);
	BOOL launchScyllaDump(string scylla,int pid, int curEip,string dumpFileName);
	BOOL existFile (string name);

};

