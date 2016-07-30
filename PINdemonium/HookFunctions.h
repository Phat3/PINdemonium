#pragma once
#include <map>
#include "pin.H"
#include "ProcessInjectionModule.h"
#include "ProcInfo.h"


#define VIRTUALFREE_INDEX 0
#define CREATEPROCESS_INDEX 1
/*
#define VIRTUALALLOC_INDEX 2
#define RTLALLOCATEHEAP_INDEX 3
#define ISDEBUGGERPRESENT_INDEX 4
#define RTLREALLOCATEHEAP_INDEX 5
*/

class HookFunctions
{
public:
	HookFunctions(void);
	~HookFunctions(void);
	void hookDispatcher(IMG img);

private:
	
	std::map<string, int> functionsMap;
};

