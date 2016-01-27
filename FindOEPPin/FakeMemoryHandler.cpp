#include "FakeMemoryHandler.h"


typedef struct _MODULEINFO {
    W::LPVOID lpBaseOfDll;
    W::DWORD  SizeOfImage;
    W::LPVOID EntryPoint;
	} MODULEINFO, *LPMODULEINFO;

typedef W::DWORD (WINAPI *MyEnumProcessModules)(W::HANDLE hProcess, W::HMODULE *lphModule, W::DWORD cb, W::LPDWORD lpcbNeeded);
typedef W::DWORD (WINAPI *MyGetModuleInformation)(W::HANDLE hProcess, W::HMODULE HModule, LPMODULEINFO module_info, W::DWORD  cb);



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

	ADDRINT kuser = KUSER_SHARED_DATA_ADDRESS + TICK_MULTIPLIER_OFFSET;
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

	if(curReadAddr == KUSER_SHARED_DATA_ADDRESS + LOW_PART_KSYSTEM_OFFSET){
	
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

	
	if(curReadAddr == KUSER_SHARED_DATA_ADDRESS + HIGH_1_KSYSTEM_OFFSET){
	
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

	
	if(curReadAddr == KUSER_SHARED_DATA_ADDRESS + HIGH_2_KSYSTEM_OFFSET){
	
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
	fakeMem2.StartAddress = KUSER_SHARED_DATA_ADDRESS + TICK_MULTIPLIER_OFFSET;  
	fakeMem2.EndAddress = KUSER_SHARED_DATA_ADDRESS + TICK_MULTIPLIER_OFFSET + LOW_PART_KSYSTEM_OFFSET - 1; // the end of the TickMultiplier field 
	fakeMem2.func = &FakeMemoryHandler::TickMultiplierPatch; 
	fakeMemory.push_back(fakeMem2);


	FakeMemoryItem fakeMem3;
	fakeMem3.StartAddress = KUSER_SHARED_DATA_ADDRESS + LOW_PART_KSYSTEM_OFFSET;
	fakeMem3.EndAddress = KUSER_SHARED_DATA_ADDRESS + HIGH_2_KSYSTEM_OFFSET;
	fakeMem3.func = &FakeMemoryHandler::KSystemTimePatch;
	fakeMemory.push_back(fakeMem3);
}

BOOL getMemoryRange(ADDRINT address, MemoryRange& range){
		
		W::MEMORY_BASIC_INFORMATION mbi;
		int numBytes = W::VirtualQuery((W::LPCVOID)address, &mbi, sizeof(mbi));
		if(numBytes == 0){
			MYERRORE("VirtualQuery failed");
			return FALSE;
		}
	
		int start =  (int)mbi.BaseAddress;
		int end = (int)mbi.BaseAddress+ mbi.RegionSize;
		//get the stack base address by searching the highest address in the allocated memory containing the stack Address
	//	MYINFO("state %08x   %08x",mbi.State,mbi.Type);
		if((mbi.State == MEM_COMMIT || mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE ||  mbi.Type == MEM_PRIVATE) &&
			start <=address && address <= end){
			//MYINFO("Adding start %08x ",(int)mbi.BaseAddress);
			range.StartAddress = start;
			range.EndAddress = end;
			return TRUE;
		}
		else{
			MYERRORE("Address %08x  not inside mapped memory from %08x -> %08x or Type/State not correct ",address,start,end);
			return  FALSE;
		}
		
}

VOID printProcessHeap(){
	MYINFO("-------- BEGIN ----------");
	W::SIZE_T BytesToAllocate;
	W::PHANDLE aHeaps;
	//getting the number of ProcessHeaps
	W::DWORD NumberOfHeaps = W::GetProcessHeaps(0, NULL);
    if (NumberOfHeaps == 0) {
		MYERRORE("Error in retrieving number of Process Heaps");
		return;
	}
	//Allocating space for the ProcessHeaps Addresses
	W::SIZETMult(NumberOfHeaps, sizeof(*aHeaps), &BytesToAllocate);
	aHeaps = (W::PHANDLE)W::HeapAlloc(W::GetProcessHeap(), 0, BytesToAllocate);
	if ( aHeaps == NULL) {
		MYERRORE("HeapAlloc failed to allocate space");
		return;
	} 

	W::GetProcessHeaps(NumberOfHeaps,aHeaps);
	//Adding the memory range containing the ProcessHeaps to the  genericMemoryRanges
	 for (int i = 0; i < NumberOfHeaps; ++i) {
		MemoryRange processHeap;
		if(getMemoryRange((ADDRINT) aHeaps[i],processHeap)){
			MYINFO("Init processHeaps base address  %08x -> %08x",processHeap.StartAddress,processHeap.EndAddress);
		}
    }
	MYINFO("-------- END ----------");
}


BOOL FakeMemoryHandler::CheckInCurrentDlls(UINT32 address_to_check){
	
	//MYINFO("Calling current dlls");
	
	W::HMODULE hMods[1024];
	char Buffer[2048];

	W::LPTSTR pBuffer = Buffer;

    W::DWORD cbNeeded;
	BOOL isDll = FALSE;

	W::HINSTANCE hPsapi = NULL;
	MyEnumProcessModules enumProcessModules = NULL;
	MyGetModuleInformation getModuleInformation = NULL;


	hPsapi = W::LoadLibraryA("psapi.dll");
	W::HANDLE process = W::GetCurrentProcess(); 

	MODULEINFO mi;

	enumProcessModules = (MyEnumProcessModules) W::GetProcAddress(hPsapi, "EnumProcessModules");
	getModuleInformation= (MyGetModuleInformation) W::GetProcAddress(hPsapi,"GetModuleInformation");


	if( enumProcessModules(process, hMods, sizeof(hMods), &cbNeeded))
    {
        for (int  i = 0; i < (cbNeeded / sizeof(W::HMODULE)); i++ )
        {

            getModuleInformation(process,hMods[i], &mi,sizeof(mi));
		    GetModuleFileNameA(hMods[i], pBuffer,sizeof(Buffer));
			
			//MYINFO("I've added %s to the list of know libary\n", Buffer);
			UINT32 end_addr = (UINT32)mi.lpBaseOfDll + mi.SizeOfImage;

		   // MYINFO("Module %s found at %08x - %08x\n" , Buffer , mi.lpBaseOfDll , end_addr);
			
			ProcInfo *p = ProcInfo::getInstance();
			BOOL isMain = FALSE;

			PIN_LockClient();
			IMG img = IMG_FindByAddress((UINT32)mi.lpBaseOfDll);
			PIN_UnlockClient();

			if(IMG_Valid(img)){
			isMain = IMG_IsMainExecutable(img);
			}

			if(!isMain){
				p->addLibrary(Buffer,(UINT32)mi.lpBaseOfDll,end_addr);		
			}

			FilterHandler *filterHandler = FilterHandler::getInstance();

			if(filterHandler->IsNameInFilteredArray(Buffer)){
				MYINFO("Added to the filtered array the module %s\n" , Buffer);
				filterHandler->addToFilteredLibrary(Buffer,(UINT32)mi.lpBaseOfDll,end_addr);
			}

			if(address_to_check >= (UINT32)mi.lpBaseOfDll && address_to_check <= end_addr){
				isDll = true;
			}
        }
    }
	
	
	W::FreeLibrary(hPsapi);
	
	return TRUE;

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
			//MYINFO("[DEBUG] Address violated the FakeMemory\n");
			return patchedAddr;
		}
	}

	//Check if the address is inside the WhiteListed addresses( need to return the correct value)
	if(isAddrInWhiteList(address)){
		
		//MYINFO("[DEBUG] Address is in WhiteList\n");
		return address;
	}
	//Read address is outside of the Whitelist probably in the PIN address space (need to return some random garbage)
	else{
		
		//MYINFO("Detected suspicious read at %08x ",address);
		ProcInfo *p = ProcInfo::getInstance();

		// here the whitelist is updated and we check also if the address is inside the new discovere heaps
		if(p->addProcessHeapsAndCheckAddress(address)){

			//MYINFO("@@@@@@Calling addProcessHeapAndCheckAddress\n");
			return address;
		}	  

		//p->setCurrentMappedFiles();
		/*
		if(isAddrInWhiteList(address)){
			//printProcessHeap();
			//p->printHeapList();
			return address;
		}
		*/

		//printProcessHeap();
		//p->printHeapList();
		if(CheckInCurrentDlls(address)){
			return address;
		}
		else{
			curFakeMemory = "TopoMotoTopoMotoTopoMotoTopoMotoTopoMotoTopoMotoTopoMoto";
			return NULL;
		}
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