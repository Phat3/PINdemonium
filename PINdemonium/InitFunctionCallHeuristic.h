#pragma once
#include "pin.H"
#include "WxorXHandler.h"
#include "FilterHandler.h"
#include "ProcInfo.h"
#include <fstream>
#include "ScyllaWrapperInterface.h"
namespace W{
	#include "windows.h"
	#include <tlhelp32.h>
	#include <Psapi.h>
	#include <string>
}


class InitFunctionCall
{
public:
	InitFunctionCall(void);
	~InitFunctionCall(void);
	UINT32 run(ADDRINT curEip,WriteInterval* wi);
private:
	UINT32 getFileSize(FILE * fp);
	BOOL launchIdaScript(string idaw,string idaPythonScript,string  idaPythonInput,string idaPythonOutput,string dumpFileName);
	BOOL existFile (std::string name);
};

