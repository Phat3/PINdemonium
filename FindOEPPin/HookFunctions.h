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
#define RTLREALLOCATEHEAP_INDEX 6
#define MAPVIEWOFFILE_INDEX 7
#define VIRTUALFREE_INDEX 8
#define VIRTUALQUERY_INDEX 9
#define VIRTUALPROTECT_INDEX 10
#define VIRTUALQUERYEX_INDEX 11
#define SETINFOTHREAD_INDEX 12 

class HookFunctions
{
public:
	HookFunctions(void);
	~HookFunctions(void);
	void hookDispatcher(IMG img);

private:
	std::map<string, int> functionsMap;
};

