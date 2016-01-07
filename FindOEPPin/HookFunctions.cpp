#include "HookFunctions.h"




HookFunctions::HookFunctions(void)
{
	//this->functionsMap.insert( std::pair<string,int>("VirtualAlloc",VIRTUALALLOC_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("RtlAllocateHeap",RTLALLOCATEHEAP_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("IsDebuggerPresent",ISDEBUGGERPRESENT_INDEX) );

	//TIMING FUNCTIONS 
	this->functionsMap.insert( std::pair<string,int>("GetTickCount",GETTICKCOUNT) );
	this->functionsMap.insert( std::pair<string,int>("timeGetTime",TIMEGETTIME) );
	// QueryPerformanceCounter is hooked at syscall level with the NtQueryPerformanceCounter

	this->functionsMap.insert( std::pair<string,int>("RtlReAllocateHeap",RTLREALLOCATEHEAP_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("MapViewOfFile",MAPVIEWOFFILE_INDEX) );


}


HookFunctions::~HookFunctions(void)
{
	
}


//----------------------------- HOOKED FUNCTIONS -----------------------------//

// hook the VirtualAlloc() in order to retrieve the memory range allocated and build ours data structures
// NOT USED ANYMORE, WE HOOKED THE NtAllocateVirtualMemory syscall in order to be more generic ( see HookSyscalls.cpp row 126 )
VOID VirtualAllocHook(UINT32 virtual_alloc_size , UINT32 ret_heap_address ){
  
  ProcInfo *proc_info = ProcInfo::getInstance();

  HeapZone hz;
  hz.begin = ret_heap_address;
  hz.size = virtual_alloc_size;
  hz.end = ret_heap_address + virtual_alloc_size;
  
   MYINFO("Virtualloc insert in Heap Zone %08x -> %08x",hz.begin,hz.end);

  //saving this heap zone in the map inside ProcInfo
  proc_info->insertHeapZone(hz); 

}

//hook the  HeapAllocHook() in order to retrieve the memory range allocated and build ours data structures
static HeapZone prev_heap_alloc;
VOID RtlAllocateHeapHook(int heap_alloc_size , UINT32 ret_heap_address ){
	 
	if (heap_alloc_size == 0 ){
		return;
	}
	

	ProcInfo *proc_info = ProcInfo::getInstance();
	//need this code because sometimes RTLAllocHeap is invoked twice (because of the IPOINT_AFTER insert)and the second time is the correct one
	if (prev_heap_alloc.begin == ret_heap_address){
		proc_info->removeLastHeapZone();
	
	}

	HeapZone hz;
	hz.begin = ret_heap_address;
	hz.size = heap_alloc_size;
	hz.end = ret_heap_address + heap_alloc_size;
	prev_heap_alloc =hz;
	
	//MYINFO("AllocateHeap insert in Heap Zone %08x -> %08x",hz.begin,hz.end);
	//saving this heap zone in the map inside ProcInfo
	proc_info->insertHeapZone(hz); 

}


VOID RtlReAllocateHeapHook(ADDRINT heap_address, UINT32 size ){
	
	ProcInfo *proc_info = ProcInfo::getInstance();

	HeapZone hz;
	hz.begin = heap_address;
	hz.size = size;
	hz.end = heap_address + size;
	//MYINFO("ReAllocateHeap insert in Heap Zone %08x -> %08x",hz.begin,hz.end);

	//saving this heap zone in the map inside ProcInfo
	proc_info->insertHeapZone(hz); 
}

VOID MapViewOfFileHookAfter(W::DWORD dwDesiredAccess,W::DWORD dwFileOffsetHigh, W::DWORD dwFileOffsetLow, UINT32 size,ADDRINT file_view_addr ){
	MYINFO("Found After mapViewOfFile Access %08x OffsetHigh %08x OffsetLow %08x  at %08x of size %08x ",dwDesiredAccess,dwFileOffsetHigh,dwFileOffsetLow,file_view_addr,size);
	ProcInfo *proc_info = ProcInfo::getInstance();
	proc_info->addMappedFilesAddress(file_view_addr);
}

//REMEMBER!!! : PIN wants a function pointer in the AFUNCPTR agument!!!
//avoid the detection of the debugger replacing the function IsDebuggerPresent() with a new one that returns always false
//very basic way to avoid this anti-debugging technique
bool * IsDebuggerPresentHook(){
	return false;
}


//----------------------------- HOOKED DISPATCHER -----------------------------//

//scan the image and try to hook all the function specified above
void HookFunctions::hookDispatcher(IMG img){
	//for each function that we want to hook or replace
	for (std::map<string,int>::iterator item = this->functionsMap.begin(); item != this->functionsMap.end(); ++item){
		//get the pointer to the specified function
		const char * func_name = item->first.c_str();
		RTN rtn = RTN_FindByName( img, func_name);
		//if we found a valid routine
		if(rtn != RTN_Invalid()){
			
			ADDRINT va_address = RTN_Address(rtn);
			MYINFO("Inside %s Address of %s: %08x" ,IMG_Name(img).c_str(),func_name, va_address);

			RTN_Open(rtn); 	
			int index = item->second;
			//decide what to do based on the function hooked
			//Different arguments are passed to the hooking routine based on the function
			switch(index){
				case(VIRTUALALLOC_INDEX):
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAllocHook , IARG_FUNCARG_ENTRYPOINT_VALUE,1 , IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					break;
				case(RTLALLOCATEHEAP_INDEX):
					//need to be IPOINT_AFTER because the allocated address is returned as return value
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)RtlAllocateHeapHook , IARG_FUNCARG_ENTRYPOINT_VALUE,2, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
					break;
				case(ISDEBUGGERPRESENT_INDEX):
					RTN_Replace(rtn, AFUNPTR(IsDebuggerPresentHook));
					break;

				case (GETTICKCOUNT):
					   {
						ProcInfo *pInfo = ProcInfo::getInstance();
						pInfo->addRtn("GetTickCount",va_address,va_address+RTN_Size(rtn)); // add the GetTickCount in the list of not filtered rtn
						// the handling of the GetTickCount is done by changing the value of the TickMultiplier in the kuser_shared_data when the process tries to read it
					   }
					break;
				case (TIMEGETTIME):
					   {
						ProcInfo *pInfo = ProcInfo::getInstance();
						va_address = 0x70e626c0; // Stupid pin doesn't recognize correctly the address range of timeGetTime... -.-" 
						ADDRINT end_address = 0x70e62712;
						pInfo->addRtn("timeGetTime",va_address,end_address); // add the timeGetTime in the list of not filtered rtn
						MYINFO("timeGetTime from %08x to %08x\n" , va_address,end_address);
				       }
					break;

				case(RTLREALLOCATEHEAP_INDEX):
					//IPOINT_BEFORE because the address to be realloc is passed as an input paramenter
					RTN_InsertCall(rtn,IPOINT_BEFORE,(AFUNPTR)RtlReAllocateHeapHook, IARG_FUNCARG_ENTRYPOINT_VALUE,2 , IARG_FUNCARG_ENTRYPOINT_VALUE,3, IARG_END);
					break;
				case(MAPVIEWOFFILE_INDEX):
					//need to be IPOINT_AFTER because the allocated address is returned as return value
					RTN_InsertCall(rtn,IPOINT_AFTER,(AFUNPTR)MapViewOfFileHookAfter,IARG_FUNCARG_ENTRYPOINT_VALUE,1,IARG_FUNCARG_ENTRYPOINT_VALUE,2,IARG_FUNCARG_ENTRYPOINT_VALUE,3, IARG_FUNCARG_ENTRYPOINT_VALUE,4,IARG_FUNCRET_EXITPOINT_VALUE,  IARG_END);
					break;


			}			
			RTN_Close(rtn);
		}
	}
}


