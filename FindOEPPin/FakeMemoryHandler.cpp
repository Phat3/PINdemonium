#include "FakeMemoryHandler.h"


static string res;

FakeMemoryHandler::FakeMemoryHandler(void)
{
	//Populating the ntdll function patch  table
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserApcDispatcher","\x8D\x84\x24\xDC\x02\x00\x00"));
	//ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserApcDispatcher","AAaacaneporco"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserCallbackDispatcher","\x64\x8B\x0D\x00\x00\x00\x00"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserExceptionDispatcher","\xFC\x8B\x4C\x24\x04"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("LdrInitializeThunk","\x8B\xFF\x55\x8B\xEC"));
	
}



FakeMemoryHandler::~FakeMemoryHandler(void)
{
}

ADDRINT FakeMemoryHandler::ntdllFuncPatch(ADDRINT curReadAddr, ADDRINT ntdllFuncAddr){
	string patch = ntdllHooksAddrPatch.at(ntdllFuncAddr);
	//cout << patch<< "\n";
	int delta = curReadAddr - ntdllFuncAddr;
	MYINFO("delta %d\n",delta);
	res = patch.substr(delta,string::npos);
//	cout <<"sub " <<delta << "  res " <<  res << "\n";
	ADDRINT patchAddr = (ADDRINT)&res;
	MYINFO("read at %08x containig %02x  Patched address %08x with string %02x \n",curReadAddr, *(char *)curReadAddr,patchAddr,*(char *)res.c_str());
	return patchAddr;
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
		fakeMem.EndAddress = address + patch.length();
		fakeMem.func = &FakeMemoryHandler::ntdllFuncPatch;
		fakeMemory.push_back(fakeMem);

		MYINFO("function %s addr  %08x -> %08x",funcName,fakeMem.StartAddress,fakeMem.EndAddress);

	}
	
}

ADDRINT FakeMemoryHandler::getFakeMemory(ADDRINT address){

	//Searching if address is inside the FakeMemory array
	for(std::vector<FakeMemoryItem>::iterator it = fakeMemory.begin(); it != fakeMemory.end(); ++it){
		if(it->StartAddress <= address && address <= it->EndAddress){
			MYINFO("Found address in FakeMemory %08x\n",address);
			//Executing the PatchFunction associated to this memory range which contains the address
			ADDRINT patchedAddr = it->func(address,it->StartAddress);
			//MYINFO("Found address in FakeMemory %08x ",address);
			MYINFO("Inside getFakeMem read at %08x containig %08x  Patched at %08x with %02x\n",address, *(char *)address,patchedAddr, *(*(string *)patchedAddr).c_str());
			return patchedAddr;
		}
	}
	return address;
	
}
