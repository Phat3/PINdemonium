#include "HookFunctions.h"


HookFunctions::HookFunctions(void)
{
	this->functionsMap.insert( std::pair<string,int>("VirtualAlloc",VIRTUALALLOC_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("RtlAllocateHeap",RTLALLOCATEHEAP_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("IsDebuggerPresent",ISDEBUGGERPRESENT_INDEX) );

	//TIMING FUNCTIONS 
	this->functionsMap.insert( std::pair<string,int>("GetTickCount",GETTICKCOUNT) );
	this->functionsMap.insert( std::pair<string,int>("timeGetTime",TIMEGETTIME) );
	//QueryPerformanceCounter is hooked at syscall level with the NtQueryPerformanceCounter.

}


HookFunctions::~HookFunctions(void)
{
}


//----------------------------- HOOKED FUNCTIONS -----------------------------//

//hook the VirtualAlloc() in order to retrieve the memory range allocated and build ours data structures
VOID VirtualAllocHook(UINT32 virtual_alloc_size , UINT32 ret_heap_address ){
  
  ProcInfo *proc_info = ProcInfo::getInstance();

  HeapZone hz;
  hz.begin = ret_heap_address;
  hz.size = virtual_alloc_size;
  hz.end = ret_heap_address + virtual_alloc_size;

  //saving this heap zone in the map inside ProcInfo
  proc_info->insertHeapZone(hz); 

}

//hook the  HeapAllocHook() in order to retrieve the memory range allocated and build ours data structures
VOID HeapAllocHook(UINT32 heap_alloc_size , UINT32 ret_heap_address ){
	
	if (heap_alloc_size == 0){
		return;
	}

	ProcInfo *proc_info = ProcInfo::getInstance();

	HeapZone hz;
	hz.begin = ret_heap_address;
	hz.size = heap_alloc_size;
	hz.end = ret_heap_address + heap_alloc_size;

	//saving this heap zone in the map inside ProcInfo
	proc_info->insertHeapZone(hz); 

}

//REMEMBER!!! : PIN wants a function pointer in the AFUNCPTR agument!!!
//avoid the detection of the debugger replacing the function IsDebuggerPresent() with a new one that returns always false
//very basic way to avoid this anti-debugging technique
bool * IsDebuggerPresentHook(){
	return false;
}


//-------------------------------------------------------------------------------------
//	TIMING FUNCTION HOOKS
//-------------------------------------------------------------------------------------
//	 GetTickCount and timeGetTime are more or less the same thing, 
//	 see hxxps://randomascii.wordpress.com/2013/05/09/timegettime-versus-gettickcount/
//
//-------------------------------------------------------------------------------------

VOID GetTickCountHook(UINT32 ticks , CONTEXT *ctx){
	
	char buff[1000];
	sprintf (buff,"call GetTickCount() -> ticks %d\n" , ticks);
	Config::getInstance()->writeOnTimeLog(buff);

	int tick_divisor = Config::TICK_DIVISOR;
	UINT32 ticks_fake = ticks / tick_divisor;

	PIN_SetContextReg(ctx, REG_EAX,ticks_fake);

}

UINT32 timeGetTimeHook(){

	char buff[1000];

	UINT32 ticks = W::GetTickCount();
	
	sprintf (buff,"call timeGetTime() -> ticks %d\n" , ticks);
	Config::getInstance()->writeOnTimeLog(buff);

	int tick_divisor = Config::TICK_DIVISOR;

	return ticks/tick_divisor;
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
			MYINFO("Address of %s: %08x\n" ,func_name, va_address);

			RTN_Open(rtn); 	
			int index = item->second;
			MYINFO("index of %s is %d",func_name,index);
			//decide what to do based on the function hooked
			//Different arguments are passed to the hooking routine based on the function
			switch(index){
				case(VIRTUALALLOC_INDEX):
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAllocHook , IARG_G_ARG1_CALLEE , IARG_G_RESULT0, IARG_END);
					break;
				case(RTLALLOCATEHEAP_INDEX):
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)HeapAllocHook , IARG_G_ARG2_CALLEE, IARG_G_RESULT0, IARG_END);
					break;
				case(ISDEBUGGERPRESENT_INDEX):
					RTN_Replace(rtn, AFUNPTR(IsDebuggerPresentHook));
					break;
				case (GETTICKCOUNT):
					   {
						REGSET regsIn;
						REGSET_AddAll(regsIn);
						REGSET regsOut;
						REGSET_AddAll(regsOut);
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetTickCountHook, IARG_G_RESULT0, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_END);
				       }
					break;
				case (TIMEGETTIME):
					   {
						RTN_Replace(rtn, AFUNPTR(timeGetTimeHook));
						//Using the following approach Exait can't call the GetPluginName function for reasons...
						/*
						REGSET regsIn;
						REGSET_AddAll(regsIn);
						REGSET regsOut;
						REGSET_AddAll(regsOut);
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetTickCountHook, IARG_G_RESULT0, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_END);
						*/
				       }
					break;

			}			
			RTN_Close(rtn);
		}
	}
}


