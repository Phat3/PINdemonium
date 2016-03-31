#pragma once
#include <map>
#include "pin.H"
#include "ProcInfo.h"
#include "FilterHandler.h"

#define TICK_MULTIPLIER_OFFSET 0x4
#define TICK_MULTIPLIER_SIZE 0x3
#define LOW_PART_INTERRUPT_TIME_OFFSET 0x8
#define HIGH_1_INTERRUPT_TIME_OFFSET 0xc
#define HIGH_2_INTERRUPT_TIME_OFFSET 0x10
#define LOW_PART_SYSTEM_TIME_OFFSET 0x14
#define HIGH_1_SYSTEM_TIME_OFFSET 0x18
#define HIGH_2_SYSTEM_TIME_OFFSET 0x1c

//string containing the current faked memory NB need to static because it need to survive and been accessible in the HandleRead callback inside PINshield
static string curFakeMemory;
//ntdll map associate the name of the function to hook with the patch value
//<"KiUserApcDispatcher","\x8b..">
static std::map<string,string> ntdllHooksNamesPatch;
//ntdll map populated at runtime resoving the name of the Function with its address
//<0x77dff2ac,"\x8b..">
static std::map<ADDRINT,string> ntdllHooksAddrPatch;

typedef struct _MODULEINFO {
    W::LPVOID lpBaseOfDll;
    W::DWORD  SizeOfImage;
    W::LPVOID EntryPoint;
	} MODULEINFO, *LPMODULEINFO;

typedef W::DWORD (WINAPI *MyEnumProcessModules)(W::HANDLE hProcess, W::HMODULE *lphModule, W::DWORD cb, W::LPDWORD lpcbNeeded);
typedef W::DWORD (WINAPI *MyGetModuleInformation)(W::HANDLE hProcess, W::HMODULE HModule, LPMODULEINFO module_info, W::DWORD  cb);

/*function which return the ADDRINT containing the fake memory content for the curAddr address
	curAddr: current address which is queried
	startAddr: Startaddress of the FakeMemoryItem which contain the curAddr (used to take care of offsets inside the FakeMemoryItem range)
	return: the address of the faked memory
*/
typedef ADDRINT (* fakeMemoryFunction)(ADDRINT curAddr, ADDRINT startAddr);

typedef struct FakeMemoryItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
	fakeMemoryFunction func;

}FakeMemoryItem;


class FakeReadHandler
{
private:
	//list containig the MemoryAddress which needs to me faked
	std::vector<FakeMemoryItem> fakeMemory;
	ProcInfo  *pInfo;
	// fakeMemoryFunction to handle ntdll inspection
	static ADDRINT ntdllFuncPatch(ADDRINT curReadAddr, ADDRINT ntdllFuncAddr);
	static ADDRINT TickMultiplierPatch(ADDRINT curReadAddr, ADDRINT addr);
	static ADDRINT InterruptTimePatch(ADDRINT curReadAddr, ADDRINT addr);
	static ADDRINT SystemTimePatch(ADDRINT curReadAddr, ADDRINT addr);
	//attributes for the  load library psapi
	MyEnumProcessModules enumProcessModules;
	MyGetModuleInformation getModuleInformation;
	W::HINSTANCE hPsapi;

public:
	FakeReadHandler(void);
	~FakeReadHandler(void);
	VOID initFakeMemory();
	static BOOL isAddrInWhiteList(ADDRINT address);
	BOOL CheckInCurrentDlls(UINT32 address_to_check);
	ADDRINT getFakeMemory(ADDRINT address, ADDRINT eip);
};