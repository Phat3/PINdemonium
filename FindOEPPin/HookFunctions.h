#pragma once

#include <map>
#include "pin.H"
#include "ProcInfo.h"
namespace W{
	#include "Winternl.h"
}

typedef struct _syscall_t {
    ADDRINT syscall_number;
    union {
        ADDRINT args[16];
        struct {
            ADDRINT arg0, arg1, arg2, arg3;
            ADDRINT arg4, arg5, arg6, arg7;
        };
    };
} syscall_t;


typedef struct _SYSTEM_PROCESS_INFO
{
    W::ULONG                   NextEntryOffset;
    W::ULONG                   NumberOfThreads;
    W::LARGE_INTEGER           Reserved[3];
    W::LARGE_INTEGER           CreateTime;
    W::LARGE_INTEGER           UserTime;
    W::LARGE_INTEGER           KernelTime;
    W::UNICODE_STRING          ImageName;
    W::ULONG                   BasePriority;
    W::HANDLE                  ProcessId;
	W::HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO,*PSYSTEM_PROCESS_INFO;


#define VIRTUALALLOC_INDEX 0
#define RTLALLOCATEHEAP_INDEX 1
#define ISDEBUGGERPRESENT_INDEX 2

class HookFunctions
{
public:
	HookFunctions(void);
	~HookFunctions(void);
	void hookDispatcher(IMG img);

private:
	std::map<string, int> functionsMap;
	std::map<unsigned long,string> syscallsMap;
	std::map<string,AFUNPTR> syscallsHooks;
	void enumSyscalls();

};

