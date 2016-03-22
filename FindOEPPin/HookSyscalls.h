#pragma once

#include <map>
#include "pin.H"
#include "Config.h"

namespace W{
	#include "windows.h"
	#include "Winternl.h"
}

#include "ProcInfo.h"

//--------------- HELPER DATA STRUCTURES --------------//

#define SYSTEM_PROCESS_INFORMATION 5
#define SYSTEM_HANDLE_INFORMATION 16

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

typedef struct _SYSTEM_HANDLE
{
    W::ULONG ProcessId;
    W::BYTE ObjectTypeNumber;
    W::BYTE Flags;
    W::USHORT Handle;
    W::PVOID Object;
    W::ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    W::ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];

} SYSTEM_HANDLE_INFORMATION_STRUCT, *PSYSTEM_HANDLE_INFORMATION_STRUCT;

//information about the process that the malware wants to open
typedef struct _CLIENT_ID
{
     W::PVOID UniqueProcess;
     W::PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

//function signature of our hook function
typedef void (* syscall_hook)(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);

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
	//static void NtQuerySystemInformationHook(syscall_t *sc,CONTEXT *ctx, SYSCALL_STANDARD std);
	static void NtQueryPerformanceCounterHook(syscall_t *sc,CONTEXT *ctx, SYSCALL_STANDARD std);
	static void NtQuerySystemInformationHookExit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	static void NtOpenProcessEntry(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	static void NtWriteVirtualMemoryHook(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	static void NtAllocateVirtualMemoryHook(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	static void NtMapViewOfSectionHook(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	static void NtRequestWaitReplyPortHook(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
	static void NtQueryInformationProcessHook(syscall_t *sc , CONTEXT *ctx , SYSCALL_STANDARD std);
	//Helpers
	static void syscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
	static void syscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
	static void syscallGetArguments(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...);
	//DEBUG
	static void printArgs(syscall_t * sc);
	static void printRegs(CONTEXT * ctx);
};

