#include "OepFinder.h"


OepFinder::OepFinder(void){
	this->wxorxHandler = WxorXHandler::getInstance();
}

OepFinder::~OepFinder(void){
}

static bool start_dump = false;

//update the write set manager
VOID handleWrite(ADDRINT ip, ADDRINT end_addr, UINT32 size, void *handler){		
	FilterHandler *filterHandler = FilterHandler::getInstance();
	//check if the target address belongs to some filtered range		
	if(!filterHandler->isFilteredWrite(end_addr,ip)){
		//if not update the write set		
		WxorXHandler *WHandler = (WxorXHandler *)handler;
		WHandler->writeSetManager(ip, end_addr, size);
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
    MYINFO("uscitos  1");
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
	UINT32 writeItemIndex=-1;
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
	writeItemIndex = wxorxHandler->getWxorXindex(curEip);
	//W xor X broken
	if(writeItemIndex != -1 ){
		WriteInterval item = wxorxHandler->getWritesSet()[writeItemIndex];
		//not the first broken in this write set		
		if(item.getBrokenFlag()){
			//if INTER_WRITESET_ANALYSIS_ENABLE flag is enable check if inter section JMP and trigger analysis
			Config *config = Config::getInstance();
			if(config->INTER_WRITESET_ANALYSIS_ENABLE == true){ 				
				interWriteSetJMPAnalysis(curEip,prev_ip,ins,writeItemIndex,item );
			}
		}
		//first broken in this write set ---> analysis and dump ---> set the broken flag of this write ionterval 
		else{
			MYPRINT("\n\n-------------------------------------------------------------------------------------------------------");
			MYPRINT("------------------------------------ NEW STUB FROM begin: %08x TO %08x -------------------------------------",item.getAddrBegin(),item.getAddrEnd());
			MYPRINT("-------------------------------------------------------------------------------------------------------");
			MYINFO("Current EIP %08x",curEip);
			int result = this->DumpAndFixIAT(curEip);
			Config::getInstance()->setWorking(result);
			this->analysis(item, ins, prev_ip, curEip,result);
			wxorxHandler->setBrokenFlag(writeItemIndex);
			Config::getInstance()->incrementDumpNumber(); //Incrementing the dump number even if Scylla is not successful
				
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


void OepFinder::interWriteSetJMPAnalysis(ADDRINT curEip,ADDRINT prev_ip,INS ins,UINT32 writeItemIndex, WriteInterval item){	
	WxorXHandler *wxorxH = WxorXHandler::getInstance();
	ProcInfo *pInfo = ProcInfo::getInstance();
	Config *config = Config::getInstance();
	//long jump detected intra-writeset ---> trigger analysis and dump
	UINT32 currJMPLength = std::abs( (int)curEip - (int)prev_ip);
	if( currJMPLength > item.getThreshold()){
		//Check if the current WriteSet has already dumped more than WRITEINTERVAL_MAX_NUMBER_JMP times
		//and check if the previous instruction was in the library (Long jump because return from Library)
		if(item.getCurrNumberJMP() < config->WRITEINTERVAL_MAX_NUMBER_JMP  && !pInfo->isLibraryInstruction(prev_ip)){
			//Try to dump and Fix the IAT if successful trigger the analysis
			MYPRINT("\n\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
			MYPRINT("- - - - - - - - - - - - - - JUMP NUMBER %d OF LENGHT %d  IN STUB FORM %08x TO %08x- - - - - - - - - - - - - -",item.getCurrNumberJMP(),currJMPLength, item.getAddrBegin(),item.getAddrEnd());
			MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
			MYINFO("Current EIP %08x",curEip);
			int result = this->DumpAndFixIAT(curEip);
			config->setWorking(result);
			this->analysis(item, ins, prev_ip, curEip , result);
			wxorxH->incrementCurrJMPNumber(writeItemIndex);
			config->incrementDumpNumber(); //Incrementing the dump number even if Scylla is not successful
		}				
	}
}

BOOL OepFinder::analysis(WriteInterval item, INS ins, ADDRINT prev_ip, ADDRINT curEip , int dumpAndFixResult){
	//call the proper heuristics
	//we have to implement it in a better way!!
	item.setLongJmpFlag(Heuristics::longJmpHeuristic(ins, prev_ip));
	item.setEntropyFlag(Heuristics::entropyHeuristic());
	item.setJmpOuterSectionFlag(Heuristics::jmpOuterSectionHeuristic(ins, prev_ip));
	item.setPushadPopadFlag(Heuristics::pushadPopadHeuristic());
	MYINFO("CURRENT WRITE SET SIZE : %d\t START : %08x\t END : %08x\t FLAG : %d", (item.getAddrEnd() - item.getAddrBegin()), item.getAddrBegin(), item.getAddrEnd(), item.getBrokenFlag());
	UINT32 error = Heuristics::initFunctionCallHeuristic(curEip,&item);
	
	// Now we have to discover if there are any heap zones and in that case create the stub to restore before the program execution
	ProcInfo *pInfo = ProcInfo::getInstance();

	std::vector<HeapZone> hzs = pInfo->getHeapMap();
	
	if(hzs.size() > 0){

		int size_allocated = 1000;
		int base_size = 1000;
		int size_remainder = size_allocated;
		int offset = 0;
		
		unsigned char *hz_maps = (unsigned char *) malloc(size_allocated); // used to store the information about the mapping of the current heap zones 
		unsigned char *hz_data;
		HeapZone hz;
		unsigned int hz_begin;
		unsigned int hz_size;

		for( int i=0;i<hzs.size();i++ ){

			hz = hzs.at(i);
			hz_begin = hz.begin;
			hz_size  = hz.size;

			memcpy(hz_maps+offset, &hz_begin, sizeof(int));
			memcpy(hz_maps+offset+sizeof(int), &hz_size, sizeof(int));

			size_remainder -= sizeof(int)*2; // calculating the remainder size 

			if(size_remainder - 8 <= 0 ){  // we will have space to allocate other stuff? 
				size_allocated += base_size; // increment the size_allocated
				realloc(hz_maps,size_allocated); // and realloc the buffer 
			}
			offset+=sizeof(int)*2;
		}

		// here we have all the information that we need to restore the heap zones inside the hz_maps buffer 
		// let's add it as a section inside the taken dump

		ScyllaWrapperInterface *scylla_wrapper = ScyllaWrapperInterface::getInstance();
		Config *config = Config::getInstance();

		string dump_path = config->getCurrentDumpFilePath();

		if(!existFile(dump_path)){ // this is the case in which we have a not working dump but we want to add anyway the .heap 
			dump_path = config->getNotWorkingPath();
		}
		if(!existFile(dump_path)){
			MYINFO("[CRITICAL ERROR]Dump file not found\n");
			return OEPFINDER_HEURISTIC_FAIL;
		}

		// and convert it into the WCHAR representation 
		std::wstring widestr = std::wstring(dump_path.begin(), dump_path.end());
		const wchar_t* widecstr = widestr.c_str();

		// adding the section that contains the information about the mapping of the heap zones 
		scylla_wrapper->loadScyllaLibary();
		unsigned int hmaps_address = scylla_wrapper->ScyllaWrapAddSection(widecstr, ".hmaps" , size_allocated , 0 , hz_maps);
		scylla_wrapper->unloadScyllaLibrary();	

		std::string heap_sec_name;

		unsigned int sec_address;
	
		// now we have to add the data for all the heap zones as sections 
		for(int i=0;i<hzs.size();i++ ){
			 
			hz = hzs.at(i);
			hz_begin = hz.begin;
			hz_size  = hz.size;
			hz_data = (unsigned char *)malloc(hz_size);
			PIN_SafeCopy(hz_data , (void const *)hz_begin , hz_size);

			scylla_wrapper->loadScyllaLibary();
			sec_address = scylla_wrapper->ScyllaWrapAddSection(widecstr, "heap", size_allocated , 0 , hz_data);
			scylla_wrapper->unloadScyllaLibrary();	
		}

		// this is the address of the last section inserted 
		// this will be hardcoded inside the loader-stub 
		printf("LAST ADDRESS: %08x\n" , sec_address);

		// now we have to add the stub 
		unsigned char stub[1000];








	}

	


	//write the heuristic results on ile
	Config::getInstance()->writeOnReport(curEip, item);
	return OEPFINDER_HEURISTIC_FAIL;
}

UINT32 OepFinder::DumpAndFixIAT(ADDRINT curEip){
	//Getting Current process PID and Base Address
	UINT32 pid = W::GetCurrentProcessId();
	Config * config = Config::getInstance();
	string outputFile = config->getCurrentDumpFilePath();
	string tmpDump = config->getNotWorkingPath();
	//std::wstring tmpDump_w = std::wstring(tmpDump.begin(), tmpDump.end());
	string plugin_full_path = config->PLUGIN_FULL_PATH;	
	MYINFO("Calling scylla with : Current PID %d, Current output file dump %s, Plugin %d",pid, config->getCurrentDumpFilePath().c_str(), config->PLUGIN_FULL_PATH.c_str());
	// -------- Scylla launched as an exe --------	
	ScyllaWrapperInterface *sc = ScyllaWrapperInterface::getInstance();	
	UINT32 result = sc->launchScyllaDumpAndFix(pid, curEip, outputFile, tmpDump, config->CALL_PLUGIN_FLAG, config->PLUGIN_FULL_PATH);
	if(result != SCYLLA_SUCCESS_FIX){
		MYERRORE("Scylla execution Failed error %d ",result);
		return result;
	};
	MYINFO("Scylla execution Success");
	return 1;
}

BOOL OepFinder::existFile (std::string name) {
	if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}
