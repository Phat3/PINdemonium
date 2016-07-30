#include "OepFinder.h"


OepFinder::OepFinder(void){
	this->wxorxHandler = WxorXHandler::getInstance();
	this->report = Report::getInstance();
}

OepFinder::~OepFinder(void){
}

static bool start_dump = false;

//update the write set manager
VOID handleWrite(ADDRINT ip, ADDRINT start_addr, UINT32 size, void *handler){		
	FilterHandler *filterHandler = FilterHandler::getInstance();
	//check if the target address belongs to some filtered range		
	if(!filterHandler->isFilteredWrite(start_addr,ip)){
		//if not update the write set		
		WxorXHandler *WHandler = (WxorXHandler *)handler;
		WHandler->writeSetManager(start_addr, size);
	}	
}

//check if the current instruction is a pushad or a popad
//if so then set the proper flags in ProcInfo
void OepFinder::handlePopadAndPushad(INS ins){
	string s = INS_Disassemble(ins);
	if( s.compare("popad ") == 0){
		ProcInfo::getInstance()->setPopadFlag(TRUE);
		return;
	}
	if( s.compare("pushad ") == 0){
		ProcInfo::getInstance()->setPushadFlag(TRUE);
		return;
	}
}

//connect debug
static void ConnectDebugger()
{
    if (PIN_GetDebugStatus() != DEBUG_STATUS_UNCONNECTED){
		 MYINFO("errore  1");
		 return;
	}
    DEBUG_CONNECTION_INFO info;
    if (!PIN_GetDebugConnectionInfo(&info) || info._type != DEBUG_CONNECTION_TYPE_TCP_SERVER){
		  MYINFO("errore  3");
		 return;
	}
    
	int timeout = 30000;
	DEBUG_CONNECTION_INFO infoDbg;
	PIN_GetDebugConnectionInfo(&infoDbg);
	GdbDebugger::getInstance()->connectRemote(infoDbg._tcpServer._tcpPort);
    if (PIN_WaitForDebuggerToConnect(timeout))
        return;
}

//insert a breakpoint on the current instruction
static VOID DoBreakpoint(const CONTEXT *ctxt, THREADID tid, ADDRINT ip)
{	
    // Construct a string that the debugger will print when it stops.  If a debugger is
    // not connected, no breakpoint is triggered and execution resumes immediately.
    PIN_ApplicationBreakpoint(ctxt, tid, FALSE, "DEBUGGER");
}



// - Check if the current instruction is a write  ----> add the instrumentation routine that register the write informations
// - Chek if the current instruction belongs to a library  -----> return
// - Chek if the current instruction is a popad or a pushad  -----> update the flag in ProcInfo
// - Check if the current instruction broke the W xor X law  -----> trigger the heuristics and write the report
// - Set the previous ip to the current ip ( useful for some heuristics like jumpOuterSection )
UINT32 OepFinder::IsCurrentInOEP(INS ins){
	FilterHandler *filterHandler = FilterHandler::getInstance();
	ProcInfo *proc_info = ProcInfo::getInstance();		
	int heap_index = -1;
	ADDRINT curEip = INS_Address(ins);
	ADDRINT prev_ip = proc_info->getPrevIp();
	//check if current instruction is a write
	if(wxorxHandler->isWriteINS(ins)){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_PTR, this->wxorxHandler, IARG_END);
	}
	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(proc_info->isKnownLibraryInstruction(curEip)){
		return OEPFINDER_INS_FILTERED; 
	}
	//check if the current instruction is a popad or a pushad
	this->handlePopadAndPushad(ins);	
	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	WriteInterval* item = wxorxHandler->getWxorXinterval(curEip);
	//W xor X broken
	if(item != NULL ){
		Config *config = Config::getInstance();
		if(config->getDumpNumber() < config->SKIP_DUMP ){
			//MYINFO("Skipping  Dump Number: %d Dumps to skip: %d", (int)Config::getInstance()->getDumpNumber(), config->SKIP_DUMP);
			UINT32 currJMPLength = std::abs( (int)curEip - (int)prev_ip);
			skipCurrentDump(item,currJMPLength);
			return OEPFINDER_SKIPPED_DUMP;
		}
		//not the first broken in this write set		
		if(item->getBrokenFlag()){
			//MYINFO("%08x -> %s -> %s",curEip,INS_Disassemble(ins).c_str(),RTN_FindNameByAddress(curEip).c_str());
			//if INTER_WRITESET_ANALYSIS_ENABLE flag is enable check if inter section JMP and trigger analysis	
			if(config->INTER_WRITESET_ANALYSIS_ENABLE == true){ 				
				intraWriteSetJMPAnalysis(curEip,prev_ip,ins,item );
			}
		}
		//first broken in this write set ---> analysis and dump ---> set the broken flag of this write ionterval 
		else{
			MYPRINT("\n\n-------------------------------------------------------------------------------------------------------");
			MYPRINT("------------------------------------ NEW STUB begin: %08x TO %08x -------------------------------------",item->getAddrBegin(),item->getAddrEnd());
			MYPRINT("-------------------------------------------------------------------------------------------------------\n");
			MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
			MYPRINT("- - - - - - - - - - - - - - - - - - - - - STAGE 1: DUMPING - - - - - - - - - - - - - - - - - - - - - - - - -");
			MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
			MYINFO("Current EIP %08x",curEip);
			Config::getInstance()->setNewWorkingDirectory(false); // create the folder dump_0 inside the folder associated to this timestamp 
			report->createReportDump(curEip,item->getAddrBegin(),item->getAddrEnd(),Config::getInstance()->getDumpNumber(),false,W::GetCurrentProcessId());
			int result = this->DumpAndFixIAT(curEip);
			this->DumpAndCollectHeap(item,curEip,result);
			Config::getInstance()->setWorking(result);
			MYPRINT("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
			MYPRINT("- - - - - - - - - - - - - - - - - - - - - STAGE 3: ANALYZING DUMP - - - - - - - - - - - - - - - - - - - - - -");
			MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
			this->analysis(item, ins, prev_ip, curEip,result);
			item->setBrokenFlag(true);
			
			Config::getInstance()->incrementDumpNumber(); //Incrementing the dump number even if Scylla is not successful
			//W::DebugBreak();
			report->closeReportDump();
				
		}
		// If we want to debug the program manually let's set the breakpoint after the triggered analysis
		if(Config::ATTACH_DEBUGGER){
			INS_InsertCall(ins,  IPOINT_BEFORE, (AFUNPTR)DoBreakpoint, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
		}
		proc_info->setPrevIp(INS_Address(ins));
	}
	//update the previous IP
	proc_info->setPrevIp(INS_Address(ins));

	return OEPFINDER_NOT_WXORX_INST;
}


void OepFinder::intraWriteSetJMPAnalysis(ADDRINT curEip,ADDRINT prev_ip,INS ins, WriteInterval *item){	
	MYPRINT("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
	MYPRINT("- - - - - - - - - - - - - - - - - - INTRA-WRITESET ANALYSIS TRIGGERED! - - - - - - - - - - - - - - - - - - - -");
	WxorXHandler *wxorxH = WxorXHandler::getInstance();
	ProcInfo *pInfo = ProcInfo::getInstance();
	Config *config = Config::getInstance();
	//long jump detected intra-writeset ---> trigger analysis and dump
	UINT32 currJMPLength = std::abs( (int)curEip - (int)prev_ip);
	UINT32 JMPtreshold = item->getThreshold();
	if( currJMPLength > JMPtreshold){
		//Check if the current WriteSet has already dumped more than WRITEINTERVAL_MAX_NUMBER_JMP times
		//and check if the previous instruction was in the library (Long jump because return from Library)
		if(item->getCurrNumberJMP() < config->WRITEINTERVAL_MAX_NUMBER_JMP  && !pInfo->isLibraryInstruction(prev_ip)){
			
			//Try to dump and Fix the IAT if successful trigger the analysis
			MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
	        MYPRINT("- - - - - - - - - - - - - - - - - - INTRA-DUMP ANALYSIS TRIGGERED! - - - - - - - - - - - - - - - - - - - -");
			 MYPRINT("- - - - - - - - - - - - - - - - - -currJMPLength: %d - Treshold: %d - - - - - - - - - - - - - - - - - - - -", currJMPLength,JMPtreshold);
			MYPRINT("- - - - - - - - - JUMP NUMBER %d OF LENGTH %d  IN STUB FROM %08x TO %08x- - - - - - - - - - - - - -\n",item->getCurrNumberJMP(),currJMPLength, item->getAddrBegin(),item->getAddrEnd());
			MYINFO("Current EIP %08x",curEip);
			report->createReportDump(curEip,item->getAddrBegin(),item->getAddrEnd(),Config::getInstance()->getDumpNumber(),true,W::GetCurrentProcessId());
			Config::getInstance()->setNewWorkingDirectory(false); // create a new folder to store the dump 
			int result = this->DumpAndFixIAT(curEip);
			this->DumpAndCollectHeap(item,curEip,result);
			config->setWorking(result);
			this->analysis(item, ins, prev_ip, curEip , result);
			report->closeReportDump(); //close the current dump report
			item->incrementCurrNumberJMP();
			config->incrementDumpNumber(); //Incrementing the dump number even if Scylla is not successful
		}				
	}else{
		MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
		MYPRINT("- - - - - - - - - - - - - - - - - INTRA-DUMP SKIPPED - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
		MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
	}
}

/*
Skip the current dump
*/
VOID OepFinder::skipCurrentDump(WriteInterval* item, UINT32 currJMPLength ){
	if(!item->getBrokenFlag()){
		item->setBrokenFlag(true);
		Config::getInstance()->incrementDumpNumber();
	}
	else{
		if(Config::getInstance()->INTER_WRITESET_ANALYSIS_ENABLE == true && currJMPLength > item->getThreshold()){
			item->incrementCurrNumberJMP();
			Config::getInstance()->incrementDumpNumber();
		}
	}
	
}


BOOL OepFinder::analysis(WriteInterval* item, INS ins, ADDRINT prev_ip, ADDRINT curEip , int dumpAndFixResult){
	//call the proper heuristics
	//we have to implement it in a better way!!
	Heuristics::longJmpHeuristic(ins, prev_ip);
	Heuristics::entropyHeuristic();
	Heuristics::jmpOuterSectionHeuristic(ins, prev_ip);
	Heuristics::pushadPopadHeuristic();
	//Heuristics::initFunctionCallHeuristic(curEip,&item);

	vector<string> dumps_to_analyse;
	
	dumps_to_analyse.push_back(Config::getInstance()->getCurrentDumpPath());
	Heuristics::yaraHeuristic(dumps_to_analyse);

	MYINFO("CURRENT WRITE SET SIZE : %d\t START : 0x%08x\t END : 0x%08x\t BROKEN-FLAG : %d", (item->getAddrEnd() - item->getAddrBegin()), item->getAddrBegin(), item->getAddrEnd(), item->getBrokenFlag());

	//write the heuristic results on ile
	return OEPFINDER_HEURISTIC_FAIL;
}

UINT32 OepFinder::DumpAndFixIAT(ADDRINT curEip){
	//Getting Current process PID and Base Address
	UINT32 pid = W::GetCurrentProcessId();
	Config * config = Config::getInstance();
	string outputFile = config->getWorkingDumpPath();
	string reconstructed_imports_file  = config->getCurrentReconstructedImportsPath();
	string tmpDump = outputFile + "_dmp";
	//std::wstring tmpDump_w = std::wstring(tmpDump.begin(), tmpDump.end());
	string plugin_full_path = config->PLUGIN_FULL_PATH;	
	MYINFO("Calling scylla with : Current PID %d, Current output file dump %s, Plugin %d",pid, outputFile.c_str(), config->PLUGIN_FULL_PATH.c_str());
	// -------- Scylla launched as an exe --------	
	ScyllaWrapperInterface *sc = ScyllaWrapperInterface::getInstance();	
	UINT32 result = sc->launchScyllaDumpAndFix(pid, curEip, outputFile, tmpDump, config->CALL_PLUGIN_FLAG, config->PLUGIN_FULL_PATH, reconstructed_imports_file);
	if(result != SCYLLA_SUCCESS_FIX){
		MYERRORE("Scylla execution Failed error %d ",result);
		return result;
	};
	MYINFO("Scylla execution Success");
	return SCYLLA_SUCCESS_FIX;
}


VOID OepFinder::DumpAndCollectHeap(WriteInterval* item, ADDRINT curEip, int dumpAndFixResult){

	HeapModule *heapM = HeapModule::getInstance();
	ProcInfo *pInfo = ProcInfo::getInstance();
	std::map<std::string , HeapZone> hzs = pInfo->getHeapMap();
	std::map<std::string , std::string> hzs_dumped = pInfo->getDumpedHZ();

	MYPRINT("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
	MYPRINT("- - - - - - - - - - - - - - - - - - - - - STAGE 2: DUMP HEAP - - - - - - - -- - - - - - - - - - - - - - - - -");
	MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");

	// if the curEip is in an heap zones let's save it inside the PE dumped 
	heapM->checkHeapWxorX(item, curEip,dumpAndFixResult);

	// In any case if there are any heap-zones let's save them in a separate folder
	if(hzs.size() > 0){
		heapM->saveHeapZones(hzs,hzs_dumped);
	}

}

