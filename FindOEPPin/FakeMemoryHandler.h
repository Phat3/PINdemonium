#pragma once
#include <map>
#include "pin.H"
#include "ProcInfo.h"
#include "FilterHandler.h"

#define TICK_MULTIPLIER_OFFSET 0x4
#define LOW_PART_KSYSTEM_OFFSET 0x8
#define HIGH_1_KSYSTEM_OFFSET 0xc
#define HIGH_2_KSYSTEM_OFFSET 0x10

//string containing the current faked memory NB need to static because it need to survive and been accessible in the HandleRead callback inside ToolHider
static string curFakeMemory;

//ntdll map associate the name of the function to hook with the patch value
//<"KiUserApcDispatcher","\x8b..">
static std::map<string,string> ntdllHooksNamesPatch;
//ntdll map populated at runtime resoving the name of the Function with its address
//<0x77dff2ac,"\x8b..">
static std::map<ADDRINT,string> ntdllHooksAddrPatch;

class FakeMemoryHandler
{
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

private:
	//list containig the MemoryAddress which needs to me faked
	std::vector<FakeMemoryItem> fakeMemory;
	ProcInfo *pInfo;

	// fakeMemoryFunction to handle ntdll inspection
	static ADDRINT ntdllFuncPatch(ADDRINT curReadAddr, ADDRINT ntdllFuncAddr);
	static ADDRINT TickMultiplierPatch(ADDRINT curReadAddr, ADDRINT addr);
	static ADDRINT KSystemTimePatch(ADDRINT curReadAddr, ADDRINT addr);
		

public:
	FakeMemoryHandler(void);
	~FakeMemoryHandler(void);
	VOID initFakeMemory();
	BOOL isAddrInWhiteList(ADDRINT address);
	BOOL CheckInCurrentDlls(UINT32 address_to_check);

	//
	ADDRINT getFakeMemory(ADDRINT address);
};