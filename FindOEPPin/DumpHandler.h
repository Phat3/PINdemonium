#pragma once
#include "pin.H"
#include "ProcInfo.h"
#include <sstream>
namespace W{
	#include "windows.h"
	#include <tlhelp32.h>
	#include <Psapi.h>	
}

class DumpHandler
{
public:
	DumpHandler(void);
	~DumpHandler(void);
	static BOOL launchScyllaDumpAndFix(string scylla,int pid, int curEip,string dumpFileName);
private:
	
	static BOOL existFile (string name);
	
};

