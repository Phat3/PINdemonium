#pragma once

#include <stdio.h>
#include "pin.H"
#include "OepFinder.h"
#include <time.h>
#include  "Debug.h"
#include "Config.h"
#include "FilterHandler.h"
#include "HookFunctions.h"
#include "HookSyscalls.h"
#include "PolymorphicCodeHandlerModule.h"
namespace W {
	#include <windows.h>
}


OepFinder oepf;
HookFunctions hookFun;
clock_t tStart;
ProcInfo *proc_info = ProcInfo::getInstance();
PolymorphicCodeHandlerModule pcpatcher;


//------------------------------Custom option for our FindOEPpin.dll-------------------------------------------------------------------------

KNOB <UINT32> KnobInterWriteSetAnalysis(KNOB_MODE_WRITEONCE, "pintool",
    "iwae", "0" , "specify if you want or not to track the inter_write_set analysis dumps and how many jump");

KNOB <BOOL> KnobAdvancedIATFixing(KNOB_MODE_WRITEONCE, "pintool",
    "adv-iatfix", "false" , "specify if you want or not to activate the advanced IAT fix technique");

KNOB <BOOL> KnobPolymorphicCodePatch(KNOB_MODE_WRITEONCE, "pintool",
    "poly-patch", "false" , "specify if you want or not to activate the patch in order to avoid crash during the instrumentation of polymorphic code");

KNOB <BOOL> KnobNullyfyUnknownIATEntry(KNOB_MODE_WRITEONCE, "pintool",
    "nullify-unk-iat", "false" , "specify if you want or not to nullify the IAT entry not detected as correct API by the tool\n NB: THIS OPTION WORKS ONLY IF THE OPTION adv-iatfix IS ACTIVE!");

KNOB <string> KnobPluginSelector(KNOB_MODE_WRITEONCE, "pintool",
    "plugin", "" , "specify the name of the plugin you want to launch if the IAT reconstructor fails (EX : PINdemoniumStolenAPIPlugin.dll)");

//------------------------------Custom option for our FindOEPpin.dll-------------------------------------------------------------------------


// This function is called when the application exits
// - print out the information relative to the current run
VOID Fini(INT32 code, VOID *v){
	//inspect the write set at the end of the execution
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	MYINFO("WRITE SET SIZE: %d", wxorxHandler->getWritesSet().size());
	//get the execution time
	MYINFO("Total execution Time: %.2fs", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	CLOSELOG();
	Config *config = Config::getInstance();
	config->closeReportFile();
}

// - usage 
INT32 Usage(){
	PIN_ERROR("This Pintool unpacks common packers\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

// - Get initial entropy
// - Get PE section data 
// - Add filtered library
// - Add protected libraries 
void imageLoadCallback(IMG img,void *){
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
		proc_info->PrintSections();
	}
	//build the filtered libtrary list
	ADDRINT startAddr = IMG_LowAddress(img);
	ADDRINT endAddr = IMG_HighAddress(img);
	const string name = IMG_Name(img); 
	if(!IMG_IsMainExecutable(img)){
		
		//*** If you need to protect other sections of other dll put them here ***
		// check if there are some fuction that has top be hooked in this DLL
		hookFun.hookDispatcher(img);
		// check if we have to filter this library during thwe instrumentation
		proc_info->addLibrary(name,startAddr,endAddr);
		if(filterHandler->IsNameInFilteredArray(name)){
			filterHandler->addToFilteredLibrary(name,startAddr,endAddr);
			MYINFO("Added to the filtered array the module %s\n" , name);
		}
	}
}

// trigger the instrumentation routine for each instruction
void Instruction(INS ins,void *v){
		
		oepf.IsCurrentInOEP(ins);
}

// trigger the instrumentation routine for each trace collected (useful in order to spiot polymorphic code on the current trace)
VOID Trace(TRACE trace,void *v){
	// polymorphic code handler
	pcpatcher.inspectTrace(trace);
}


// - retrive the stack base address
static VOID OnThreadStart(THREADID, CONTEXT *ctxt, INT32, VOID *){
	ADDRINT stackBase = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	ProcInfo *pInfo = ProcInfo::getInstance();
	pInfo->addThreadStackAddress(stackBase);
	pInfo->addThreadTebAddress();
	MYINFO("-----------------a NEW Thread started!--------------------\n");
}

// - if the flag is pecified start pin as launched with the flag appdebug
void initDebug(){
	DEBUG_MODE mode;
	mode._type = DEBUG_CONNECTION_TYPE_TCP_SERVER;
	mode._options = DEBUG_MODE_OPTION_STOP_AT_ENTRY;
	PIN_SetDebugMode(&mode);
}

// - set the option for the current run
void ConfigureTool(){	
	Config *config = Config::getInstance();
	config->INTER_WRITESET_ANALYSIS_ENABLE = KnobInterWriteSetAnalysis.Value();	
	config->ADVANCED_IAT_FIX = KnobAdvancedIATFixing.Value();
	config->POLYMORPHIC_CODE_PATCH = KnobPolymorphicCodePatch.Value();
	config->NULLIFY_UNK_IAT_ENTRY = KnobNullyfyUnknownIATEntry.Value();
	if(KnobInterWriteSetAnalysis.Value() > 1 && KnobInterWriteSetAnalysis.Value() <= Config::MAX_JUMP_INTER_WRITE_SET_ANALYSIS ){
		config->WRITEINTERVAL_MAX_NUMBER_JMP = KnobInterWriteSetAnalysis.Value();
	}
	else{
		MYWARN("Invalid number of jumps to track, se to default value: 2\n");
		config->WRITEINTERVAL_MAX_NUMBER_JMP = 2; // default value is 2 if we have invalid value 
	}
	//get the selected plugin or return an erro if it doen't exist
	if(KnobPluginSelector.Value().compare("") != 0){
		config->CALL_PLUGIN_FLAG = true;
		config->PLUGIN_FULL_PATH = Config::PINDEMONIUM_PLUGIN_PATH + KnobPluginSelector.Value();
		W::DWORD fileAttrib = W::GetFileAttributes(config->PLUGIN_FULL_PATH.c_str());
		//file doesn't exist
		if(fileAttrib == 0xFFFFFFFF){
			printf("THE SELECTED PLUGIN DOES NOT EXIST!\n\n\n");
			exit(-1);
		}
	}
	//don't call any plugin if it isn't selected
	else{
		config->CALL_PLUGIN_FLAG = false;
	}
}

// - if an exception is found returns all the information about it (DEBUG purposes)
EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v){	
	MYINFO("ECC!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	MYINFO("%s",PIN_ExceptionToString(pExceptInfo).c_str());
	MYINFO("ECC!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	return EHR_CONTINUE_SEARCH;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[]){

	//If we want to debug the program manually setup the proper options in order to attach an external debugger
	if(Config::ATTACH_DEBUGGER){
		initDebug();
	}
	MYINFO("->Configuring Pintool<-\n");
	//get the start time of the execution (benchmark)
	tStart = clock();	
	// Initialize pin
	PIN_InitSymbols();
	if (PIN_Init(argc, argv)) return Usage();
	//Register PIN Callbacks
	INS_AddInstrumentFunction(Instruction,0);
	PIN_AddThreadStartFunction(OnThreadStart, 0);
	IMG_AddInstrumentFunction(imageLoadCallback, 0);
	PIN_AddFiniFunction(Fini, 0);
	PIN_AddInternalExceptionHandler(ExceptionHandler,NULL);
	//get theknob args
	ConfigureTool();
	if(Config::getInstance()->POLYMORPHIC_CODE_PATCH){
		TRACE_AddInstrumentFunction(Trace,0);
	}
	proc_info->addProcAddresses();
	//init the hooking system
	HookSyscalls::enumSyscalls();
	HookSyscalls::initHooks();
	MYINFO("->Starting instrumented program<-\n");
	PIN_StartProgram();	
	return 0;
	
}
