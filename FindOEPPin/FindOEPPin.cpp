#pragma once

#include <stdio.h>
#include "pin.H"
#include "OepFinder.h"
#include <time.h>
#include  "Debug.h"
#include "Config.h"
#include "ToolHider.h"
#include "FilterHandler.h"
#include "HookFunctions.h"
#include "HookSyscalls.h"


namespace W {
	#include <windows.h>

}

ToolHider thider;
OepFinder oepf;
HookFunctions hookFun;
clock_t tStart;
static int prova =0;
ProcInfo *proc_info = ProcInfo::getInstance();



// This function is called when the application exits
VOID Fini(INT32 code, VOID *v){
	//DEBUG --- inspect the write set at the end of the execution
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	MYINFO("WRITE SET SIZE: %d", wxorxHandler->getWritesSet().size());
	//DEBUG --- get the execution time
	MYINFO("Total execution Time: %.2fs", (double)(clock() - tStart)/CLOCKS_PER_SEC);

	//ProcInfo *proc_info = ProcInfo::getInstance();
	//proc_info->PrintWhiteListedAddr();

	CLOSELOG();
	Config::getInstance()->closeReportFile();

	
}


//cc
INT32 Usage(){
	PIN_ERROR("This Pintool unpacks common packers\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}





// - Get initial entropy
// - Get PE section data 
// - Add filtered library
void imageLoadCallback(IMG img,void *){
	/*for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) ){
		for( RTN rtn= SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) ){
			MYINFO("Inside %s -> %s",IMG_Name(img).c_str(),RTN_Name(rtn).c_str());
		}
	}*/

	
	Section item;
	static int va_hooked = 0;
	ProcInfo *proc_info = ProcInfo::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();

	//get the initial entropy of the PE
	//we have to consder only the main executable and avìvoid the libraries
	if(IMG_IsMainExecutable(img)){
		
		ADDRINT startAddr = IMG_LowAddress(img);
		ADDRINT endAddr = IMG_HighAddress(img);
		proc_info->setMainIMGAddress(startAddr, endAddr);
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
	ADDRINT startAddr = IMG_LowAddress(img);
	ADDRINT endAddr = IMG_HighAddress(img);
	const string name = IMG_Name(img); 
	
	if(!IMG_IsMainExecutable(img)){	
		
		if(name.find("ntdll")!= std::string::npos){
		
		  for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) ){

			if(strcmp(SEC_Name(sec).c_str(),".text")==0){
			proc_info->addProtectedSection(SEC_Address(sec),SEC_Address(sec)+SEC_Size(sec));
			}
	      }
		}

		//*** If you need to protect other sections of other dll put them here ***

		hookFun.hookDispatcher(img);		
		
		proc_info->addLibrary(name,startAddr,endAddr);

		if(filterHandler->IsNameInFilteredArray(name)){
			filterHandler->addToFilteredLibrary(name,startAddr,endAddr);
			MYINFO("Added to the filtered array the module %s\n" , name);
		}
	}
}


// Instruction callback Pin calls this function every time a new instruction is encountered
// (Testing if better than trace iteration)
void Instruction(INS ins,void *v){

	//printf("ADDR %08x - INS %s\n" , INS_Address(ins), INS_Disassemble(ins).c_str());
	/*
	MemoryRange mem;
	
	ProcInfo::getInstance()->getMemoryRange(0x75e714a4 ,mem);

	if(mem.StartAddress <= 0x75e714a4  &&  0x75e714a4  <= mem.EndAddress){
		MYINFO("yyyyyyyyyyyyyyyyyNow the address has been mapped EIP:%08x  mapped from %08x -> %08x name %s",INS_Address(ins),mem.StartAddress,mem.EndAddress,RTN_FindNameByAddress(INS_Address(ins)).c_str());
	}
	else{ 
		MYINFO("zzzzzzCur EIP:%08x name %s ",INS_Address(ins),RTN_FindNameByAddress(INS_Address(ins)).c_str());
	}
	*/


	if(Config::EVASION_MODE){
		thider.avoidEvasion(ins);
	}

	if(Config::UNPACKING_MODE){
		oepf.IsCurrentInOEP(ins);
	}	
}



// - retrive the stack base address
static VOID OnThreadStart(THREADID, CONTEXT *ctxt, INT32, VOID *){
	ADDRINT stackBase = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	ProcInfo *pInfo = ProcInfo::getInstance();
	pInfo->addThreadStackAddress(stackBase);
	pInfo->addThreadTebAddress();
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

	FilterHandler *filterH = FilterHandler::getInstance();
	//set the filters for the libraries
	MYINFO("%s",Config::FILTER_WRITES_ENABLES.c_str());
	//filterH->setFilters(Config::FILTER_WRITES_ENABLES);
	//get the start time of the execution (benchmark)
	tStart = clock();
	// Initialize pin
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) return Usage();
	
	INS_AddInstrumentFunction(Instruction,0);

	PIN_AddThreadStartFunction(OnThreadStart, 0);
	// Register ImageUnload to be called when an image is unloaded
	IMG_AddInstrumentFunction(imageLoadCallback, 0);

	proc_info->addProcAddresses();

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	
	//init the hooking system
	HookSyscalls::enumSyscalls();
	HookSyscalls::initHooks();

	// Start the program, never returns
	PIN_StartProgram();
	
	return 0;
	
}
