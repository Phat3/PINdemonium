#include "FakeReadHandler.h"

FakeReadHandler::FakeReadHandler(void)
{
	pInfo = ProcInfo::getInstance();
	//Populating the ntdll function patch  table
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserApcDispatcher","\x8D\x84\x24\xDC\x02\x00\x00"));
	string KiUserPatch("\x64\x8B\x00\x0D\x00\x00\x00",7);// Trick to be able to insert null bytes
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserCallbackDispatcher",KiUserPatch));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserExceptionDispatcher","\xFC\x8B\x4C\x24\x04"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("LdrInitializeThunk","\x8B\xFF\x55\x8B\xEC"));

	this->hPsapi = W::LoadLibraryA("psapi.dll");
	this->enumProcessModules = (MyEnumProcessModules) W::GetProcAddress(hPsapi, "EnumProcessModules");
	this->getModuleInformation= (MyGetModuleInformation) W::GetProcAddress(hPsapi,"GetModuleInformation");
	
}

FakeReadHandler::~FakeReadHandler(void)
{
}

ADDRINT FakeReadHandler::ntdllFuncPatch(ADDRINT curReadAddr, ADDRINT ntdllFuncAddr){
	string patch = ntdllHooksAddrPatch.at(ntdllFuncAddr);
	int delta = curReadAddr - ntdllFuncAddr;
	curFakeMemory = patch.substr(delta,string::npos);
	ADDRINT patchAddr = (ADDRINT)&curFakeMemory;
	MYINFO("read at %08x containig %02x  Patched address %08x with string %02x \n",curReadAddr, *(char *)curReadAddr,patchAddr,*(char *)curFakeMemory.c_str());
	return patchAddr;
}



//populate FakeMemory Array which contains the FakeMemoryItem 
VOID FakeReadHandler::initFakeMemory(){	
	//Hide the ntdll hooks
	for(map<string,string>::iterator it = ntdllHooksNamesPatch.begin(); it != ntdllHooksNamesPatch.end();++it){
		const char  *funcName = it->first.c_str();
		string patch = it->second;
		ADDRINT address = (ADDRINT)W::GetProcAddress(W::GetModuleHandle("ntdll.dll"), funcName);		
		ntdllHooksAddrPatch.insert(std::pair<ADDRINT,string>(address,patch));
		FakeMemoryItem fakeMem;
		fakeMem.StartAddress = address;
		fakeMem.EndAddress = address + patch.length()-1; //-1 beacuse need to exclude the trailing 0x00
		fakeMem.func = &FakeReadHandler::ntdllFuncPatch;
		fakeMemory.push_back(fakeMem);
		MYINFO("Add FakeMemory ntdll %s addr  %08x -> %08x",funcName,fakeMem.StartAddress,fakeMem.EndAddress);
	}
	//add other FakeMemoryItem to the fakeMemory array for handling other cases
	
}

ADDRINT FakeReadHandler::getFakeMemory(ADDRINT address, ADDRINT eip){
	//Check if address is inside the FakeMemory array (need to modify the result of the read)
	for(std::vector<FakeMemoryItem>::iterator it = fakeMemory.begin(); it != fakeMemory.end(); ++it){
		if(it->StartAddress <= address && address <= it->EndAddress){
			//Executing the PatchFunction associated to this memory range which contains the address
			ADDRINT patchedAddr = it->func(address, it->StartAddress);
			MYINFO("Found address in FakeMemory %08x ", patchedAddr);
			MYINFO("Found FakeMemory read at %08x containig %08x  Patched at %08x containing %08x",address, *(unsigned int *)address, patchedAddr, *(unsigned int *)patchedAddr);
			MYINFO("ip : %08x in %s reading %08x and it has been redirected to : %08x",eip, RTN_FindNameByAddress(eip).c_str() , address, patchedAddr);
			return patchedAddr;			
		}
	}

		return address;

	
}

