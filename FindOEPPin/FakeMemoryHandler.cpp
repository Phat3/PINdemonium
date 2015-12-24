#include "FakeMemoryHandler.h"




FakeMemoryHandler::FakeMemoryHandler(void)
{
	pInfo = ProcInfo::getInstance();
	//Populating the ntdll function patch  table
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserApcDispatcher","\x8D\x84\x24\xDC\x02\x00\x00"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserCallbackDispatcher","\x64\x8B\x0D\x00\x00\x00\x00"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserExceptionDispatcher","\xFC\x8B\x4C\x24\x04"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("LdrInitializeThunk","\x8B\xFF\x55\x8B\xEC"));
	
}



FakeMemoryHandler::~FakeMemoryHandler(void)
{
}

ADDRINT FakeMemoryHandler::ntdllFuncPatch(ADDRINT curReadAddr, ADDRINT ntdllFuncAddr){
	string patch = ntdllHooksAddrPatch.at(ntdllFuncAddr);
	int delta = curReadAddr - ntdllFuncAddr;
	curFakeMemory = patch.substr(delta,string::npos);
	ADDRINT patchAddr = (ADDRINT)&curFakeMemory;
	//MYINFO("read at %08x containig %02x  Patched address %08x with string %02x \n",curReadAddr, *(char *)curReadAddr,patchAddr,*(char *)curFakeMemory.c_str());
	return patchAddr;
}

ADDRINT FakeMemoryHandler::TickMultiplierPatch(ADDRINT curReadAddr, ADDRINT addr){

	int tick_multiplier;
	ostringstream convert; 

	ADDRINT kuser = 0x7ffe0004;
	memcpy(&tick_multiplier,(const void *)kuser,sizeof(int));

	MYINFO("Tick multiplier is %08x\n",tick_multiplier);

	tick_multiplier = tick_multiplier / Config::TICK_DIVISOR;

	convert << tick_multiplier;

	curFakeMemory = convert.str(); 

	ADDRINT patchAddr = (ADDRINT)&curFakeMemory;

	MYINFO("Tick multiplier fake is %08x\n",curFakeMemory);

	return patchAddr;

}

ADDRINT FakeMemoryHandler::KSystemTimePatch(ADDRINT curReadAddr, ADDRINT addr){

	ostringstream convert;

	if(curReadAddr == 0x7ffe0008){
	
		W::ULONG32 LowPart;
		memcpy(&LowPart,(const void*)curReadAddr,sizeof(W::DWORD));
		MYINFO("Low part is %08x\n", LowPart);

		LowPart = LowPart / Config::LONG_DIVISOR;

		convert << LowPart;
		
		curFakeMemory = convert.str(); 

		ADDRINT patchAddr = (ADDRINT)&curFakeMemory;

		MYINFO("Low Part fake is %08x\n",curFakeMemory);

		return patchAddr;
	}

	
	if(curReadAddr == 0x7ffe000c){
	
		W::LONG32 High1Time;
		memcpy(&High1Time,(const void*)curReadAddr,sizeof(W::DWORD));
		MYINFO("High1Time part is %08x\n", High1Time);

		High1Time = High1Time / Config::LONG_DIVISOR;

		convert << High1Time;
		
		curFakeMemory = convert.str(); 

		ADDRINT patchAddr = (ADDRINT)&curFakeMemory;

		MYINFO("High1Time fake is %08x\n",curFakeMemory);

		return patchAddr;
	}

	
	if(curReadAddr == 0x7ffe0010){
	
		W::LONG32 High2Time;
		memcpy(&High2Time,(const void*)curReadAddr,sizeof(W::DWORD));
		MYINFO("High2Time part is %08x\n", High2Time);

		High2Time = High2Time / Config::LONG_DIVISOR;

		convert << High2Time;
		
		curFakeMemory = convert.str(); 

		ADDRINT patchAddr = (ADDRINT)&curFakeMemory;

		MYINFO("High2Time fake is %08x\n",curFakeMemory);

		return patchAddr;
	}



}

VOID FakeMemoryHandler::initFakeMemory(){
	//Hide the ntdll hooks
	for(map<string,string>::iterator it = ntdllHooksNamesPatch.begin(); it != ntdllHooksNamesPatch.end();++it){
		const char  *funcName = it->first.c_str();
		string patch = it->second;
		ADDRINT address = (ADDRINT)W::GetProcAddress(W::GetModuleHandle("ntdll.dll"), funcName);		
		ntdllHooksAddrPatch.insert(std::pair<ADDRINT,string>(address,patch));

		FakeMemoryItem fakeMem;
		fakeMem.StartAddress = address;
		fakeMem.EndAddress = address + patch.length()-1; //-1 beacuse need to exclude the trailing 0x00
		fakeMem.func = &FakeMemoryHandler::ntdllFuncPatch;
		fakeMemory.push_back(fakeMem);
		MYINFO("Add FakeMemory ntdll %s addr  %08x -> %08x",funcName,fakeMem.StartAddress,fakeMem.EndAddress);
	}
	//add other FakeMemoryItem to the fakeMemory array for handling other cases

	FakeMemoryItem fakeMem2;
	fakeMem2.StartAddress = 0x7ffe0004;
	fakeMem2.EndAddress = 0x7ffe0007;
	fakeMem2.func = &FakeMemoryHandler::TickMultiplierPatch;
	fakeMemory.push_back(fakeMem2);


	FakeMemoryItem fakeMem3;
	fakeMem3.StartAddress = 0x7ffe0008;
	fakeMem3.EndAddress = 0x7ffe0010;
	fakeMem3.func = &FakeMemoryHandler::KSystemTimePatch;
	fakeMemory.push_back(fakeMem3);
}

ADDRINT FakeMemoryHandler::getFakeMemory(ADDRINT address){

	//Check if address is inside the FakeMemory array (need to modify the result of the read)
	for(std::vector<FakeMemoryItem>::iterator it = fakeMemory.begin(); it != fakeMemory.end(); ++it){
		if(it->StartAddress <= address && address <= it->EndAddress){
			//MYINFO("Found address in FakeMemory %08x\n",address);
			//Executing the PatchFunction associated to this memory range which contains the address
			ADDRINT patchedAddr = it->func(address,it->StartAddress);
			//MYINFO("Found address in FakeMemory %08x ",address);
			MYINFO("Found FakeMemory read at %08x containig %08x  Patched at %08x with %08x\n",address, *(unsigned int *)address,patchedAddr, *(unsigned int *)(*(string *)patchedAddr).c_str());
			return patchedAddr;
		}
	}

	//Check if the address is inside the WhiteListed addresses( need to return the correct value)
	if(isAddrInWhiteList(address)){
		return address;
	}
	//Read address is outside of the Whitelist probably in the PIN address space (need to return some random garbage)
	else{
		MYINFO("Detected suspicious read at %08x ",address);
	
		curFakeMemory = "TopoMotoTopoMotoTopoMotoTopoMotoTopoMotoTopoMotoTopoMoto";
		return NULL;
	}
	
}


/**
Check if address is inside:
	- Main executable
	- Stack
	- Dynamically allocated memory
	- Teb
	- Peb
	- generic memory region (SharedMemory pContextData..)
	**/
BOOL FakeMemoryHandler::isAddrInWhiteList(ADDRINT address){

	//Main IMG
	if(pInfo->isInsideMainIMG(address)){
		return TRUE;
	}
	//Stack
	if(pInfo->isStackAddress(address)){
		return TRUE;
	}
	//Dynamic Allocation
	if(pInfo->searchHeapMap(address)!= -1){
		return TRUE;
	}
	
	//Library Addresses
	if (pInfo->isLibraryInstruction(address)){
		return TRUE;
	}
	//Teb Addresses
	if(pInfo->isTebAddress(address)){
		return TRUE;
	}
	//Peb Addresses
	if(pInfo->isPebAddress(address)){
		return TRUE;
	}
	//Mapped file addresses
	if(pInfo->isMappedFileAddress(address)){
		return TRUE;
	}
	//Generic memory addresses (pContextData ..)
	if(pInfo->isGenericMemoryAddress(address)){
		return TRUE;
	}

	return FALSE;
	
}