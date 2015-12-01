#pragma once

#include <stdio.h>
#include "pin.H"
#include "OepFinder.h"
#include <time.h>
#include  "Debug.h"
#include "Config.h"
#include "FilterHandler.h"
namespace W {
	#include <windows.h>
}


#define VIRTUALALLOC_INDEX 0
#define RTLALLOCATEHEAP_INDEX 1

OepFinder oepf;
clock_t tStart;
std::map<string, UINT32> HeapFunctionsMap;


// This function is called when the application exits
VOID Fini(INT32 code, VOID *v){
	//DEBUG --- inspect the write set at the end of the execution
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	MYINFO("WRITE SET SIZE: %d", wxorxHandler->getWritesSet().size());
	//DEBUG --- get the execution time
	MYINFO("Total execution Time: %.2fs", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	CLOSELOG();
	Config::getInstance()->closeReportFile();

}

//cc
INT32 Usage(){
	PIN_ERROR("This Pintool unpacks common packers\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

VOID initHeapFunctionMap(){
	HeapFunctionsMap.insert( std::pair<string,UINT32>("VirtualAlloc",VIRTUALALLOC_INDEX) );
	HeapFunctionsMap.insert( std::pair<string,UINT32>("RtlAllocateHeap",RTLALLOCATEHEAP_INDEX) );
	HeapFunctionsMap.insert( std::pair<string,UINT32>("vedere",2) );
	HeapFunctionsMap.insert( std::pair<string,UINT32>("credere",3) );
}


VOID VirtualAllocHook(UINT32 virtual_alloc_size , UINT32 ret_heap_address ){

  ProcInfo *proc_info = ProcInfo::getInstance();

  HeapZone hz;
  hz.begin = ret_heap_address;
  hz.size = virtual_alloc_size;
  hz.end = ret_heap_address + virtual_alloc_size;

  //saving this heap zone in the map inside ProcInfo
  proc_info->insertHeapZone(hz); 

}

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


void HookFuncDispatcher(IMG img, string func_name,void * func_pointer){
	/* searching for VirtualAlloc */ 
	RTN rtn = RTN_FindByName( img, func_name.c_str());
	if(rtn != RTN_Invalid()){
			
		ADDRINT va_address = RTN_Address(rtn);
		MYINFO("Address of %s: %08x\n" ,func_name.c_str(), va_address);

		RTN_Open(rtn); 	
		int index = HeapFunctionsMap.at(func_name);
		MYINFO("index of %s is %d",func_name.c_str(),index);
		//Different arguments are passed to the hooking routine based on the function
		switch(index){
			case(VIRTUALALLOC_INDEX):
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)func_pointer , IARG_G_ARG1_CALLEE , IARG_G_RESULT0, IARG_END);
				break;
			case(RTLALLOCATEHEAP_INDEX):
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)func_pointer , IARG_G_ARG2_CALLEE, IARG_G_RESULT0, IARG_END);
				break;

		}			
		RTN_Close(rtn);
	}
}

// - Get initial entropy
// - Get PE section data 
// - Add filtered library
void imageLoadCallback(IMG img,void *){

	Section item;
	static int va_hooked = 0;

	//get the initial entropy of the PE
	//we have to consder only the main executable and avìvoid the libraries
	if(IMG_IsMainExecutable(img)){
		
		ProcInfo *proc_info = ProcInfo::getInstance();
		//get the  address of the first instruction
		proc_info->setFirstINSaddress(IMG_Entry(img));
		//get the program name
		proc_info->setProcName(IMG_Name(img));
		//get the initial entropy
		MYINFO("----------------------------------------------");
		float initial_entropy = proc_info->GetEntropy();
		proc_info->setInitialEntropy(initial_entropy);
		MYINFO("----------------------------------------------");
		//retrieve the section of the PE
		for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) ){
			item.name = SEC_Name(sec);
			item.begin = SEC_Address(sec);
			item.end = item.begin + SEC_Size(sec);
			proc_info->insertSection(item);
		}
		//DEBUG
		proc_info->PrintSections();
	}
	//build the filtered libtrary list
	FilterHandler *filterH = FilterHandler::getInstance();
	ADDRINT startAddr = IMG_LowAddress(img);
	ADDRINT endAddr = IMG_HighAddress(img);
	const string name = IMG_Name(img); 

	if(!IMG_IsMainExecutable(img) && filterH->isKnownLibrary(name)){	

		HookFuncDispatcher(img,"VirtualAlloc",VirtualAllocHook);
		HookFuncDispatcher(img,"RtlAllocateHeap",HeapAllocHook);
		
		filterH->addLibrary(name,startAddr,endAddr);
	}
}




// Instruction callback Pin calls this function every time a new instruction is encountered
// (Testing if batter than trace iteration)
void Instruction(INS ins,void *v){
	if(Config::EVASION_MODE){
		//printf("dsa");
	}
	if(Config::UNPACKING_MODE){
		oepf.IsCurrentInOEP(ins);
	}
	
}


// - retrive the stack base address
static VOID OnThreadStart(THREADID, CONTEXT *ctxt, INT32, VOID *){
	ADDRINT stackBase = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	FilterHandler *filterH = FilterHandler::getInstance();
	filterH->setStackBase(stackBase);
}

void initDebug(){
	DEBUG_MODE mode;
	mode._type = DEBUG_CONNECTION_TYPE_TCP_SERVER;
	mode._options = DEBUG_MODE_OPTION_STOP_AT_ENTRY;
	PIN_SetDebugMode(&mode);
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[]){
	//If we want to debug the program manually setup the proper options in order to attach an external debugger
	if(Config::ATTACH_DEBUGGER){
		initDebug();
	}

	MYINFO("Strating prototype ins");
	initHeapFunctionMap();

	FilterHandler *filterH = FilterHandler::getInstance();
	//set the filters for the libraries
	MYINFO("%s",Config::FILTER_WRITES_ENABLES.c_str());
	filterH->setFilters(Config::FILTER_WRITES_ENABLES);
	//get the start time of the execution (benchmark)
	tStart = clock();
	// Initialize pin
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) return Usage();
	
	INS_AddInstrumentFunction(Instruction,0);

	PIN_AddThreadStartFunction(OnThreadStart, 0);
	// Register ImageUnload to be called when an image is unloaded
	IMG_AddInstrumentFunction(imageLoadCallback, 0);
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();
	
	return 0;
}
