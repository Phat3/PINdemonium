#pragma once
#include <map>
#include "pin.H"
#include "ProcInfo.h"


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
	BOOL isAddrInWhiteList(ADDRINT address);

	

	
	

public:
	FakeMemoryHandler(void);
	~FakeMemoryHandler(void);
	VOID initFakeMemory();
	//
	ADDRINT getFakeMemory(ADDRINT address);
};