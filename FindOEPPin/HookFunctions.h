#pragma once

#include <map>
#include "pin.H"
#include "ProcInfo.h"

#define VIRTUALALLOC_INDEX 0
#define RTLALLOCATEHEAP_INDEX 1
#define ISDEBUGGERPRESENT_INDEX 2
#define GETTICKCOUNT 3
#define TIMEGETTIME 4
#define QUERYPERFCOUNTER 5

class HookFunctions
{
public:
	HookFunctions(void);
	~HookFunctions(void);
	void hookDispatcher(IMG img);

private:
	std::map<string, int> functionsMap;
	std::map<unsigned long,string> syscallsMap;
	void enumSyscalls();
	
	// DEBUG
	void printSyscalls();
	

	

};

