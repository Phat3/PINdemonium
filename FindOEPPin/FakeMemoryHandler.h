#pragma once
#include <map>
#include "pin.H"
#include "ProcInfo.h"


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

	std::vector<FakeMemoryItem> fakeMemory;

	static ADDRINT ntdllFuncPatch(ADDRINT curReadAddr, ADDRINT ntdllFuncAddr);

	
	

public:
	FakeMemoryHandler(void);
	~FakeMemoryHandler(void);
	VOID initFakeMemory();
	ADDRINT getFakeMemory(ADDRINT address);
};