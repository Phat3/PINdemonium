#pragma once

#include <map>
#include "pin.H"
namespace W{
	#include "windows.h"
	#include "Winternl.h"
}

//--------------- HELPER DATA STRUCTURES --------------//

//information on the syscall
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

//informations returned by the NtSystemQueryInformation
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
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

//function signature of our hook function
typedef void (* syscall_hook)(syscall_t *sc);

//binding betweeb syscall name and the hook to be executed
static std::map<string,syscall_hook> syscallsHooks;
//binding between the ordinal of the syscall and the name of the syscall
//(we have to fill this map at runtime because ordinals numbers are not consisten between different OS version or SP)
static std::map<unsigned long,string> syscallsMap;

//--------------- END HELPER DATA STRUCTURES --------------//

class HookSyscalls
{
public:
	static void enumSyscalls();
	static void initHooks();

private:
	//Hooks
	static void NtQuerySystemInformationHook(syscall_t *sc);
	//heplers
	static void syscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
	static void syscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
	static void syscallGetArguments(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...);

};

