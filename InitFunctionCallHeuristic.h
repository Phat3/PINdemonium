#pragma once
#include "pin.H"
#include "WxorXHandler.h"
#include "ProcInfo.h"
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
	BOOL launchIdaScript(char *idaw,char *idaPythonScript,char *idaPythonInput,char *idaPythonOutput,const char * dumpFileName);
	BOOL launchScyllaDump(char *scylla,int pid, int curEip,const char *dumpFileName);
	BOOL existFile (const char *name);

};

