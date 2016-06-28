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
			Config::getInstance()->setNewWorkingDirectory(); // create the folder dump_0 inside the folder associated to this timestamp 
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
			MYPRINT("- - - - -+ - - - - - - - - - JUMP NUMBER %d OF LENGHT %d  IN STUB FORM %08x TO %08x- - - - - - - - - - - - - -",item.getCurrNumberJMP(),currJMPLength, item.getAddrBegin(),item.getAddrEnd());
			MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
			MYINFO("Current EIP %08x",curEip);
			Config::getInstance()->setNewWorkingDirectory(); // create a new folder to store the dump 
			int result = this->DumpAndFixIAT(curEip);
			config->setWorking(result);
			this->analysis(item, ins, prev_ip, curEip , result);
			wxorxH->incrementCurrJMPNumber(writeItemIndex);
			config->incrementDumpNumber(); //Incrementing the dump number even if Scylla is not successful
		}				
	}
}

UINT32 OepFinder::checkHeapWxorX(WriteInterval item, ADDRINT curEip, int dumpAndFixResult){

		// include in the PE the dump of the current heap zone in which we have break the WxorX 
	if( item.getHeapFlag() && dumpAndFixResult != SCYLLA_ERROR_FILE_FROM_PID  && dumpAndFixResult != SCYLLA_ERROR_DUMP ){
		
		unsigned char * Buffer;
		UINT32 size_write_set = item.getAddrEnd() - item.getAddrBegin();
		//prepare the buffer to copy inside the stuff into the heap section to dump 		  
		Buffer = (unsigned char *)malloc( size_write_set );
		// copy the heap zone into the buffer 
		PIN_SafeCopy(Buffer , (void const *)item.getAddrBegin() , size_write_set);	
		ScyllaWrapperInterface *scylla_wrapper = ScyllaWrapperInterface::getInstance();
		// get the name of the last dump from the Config object 
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
		// calculate where the program jump in the heap ( i.e. 0 perfectly at the begin of the heapzone ) 
		UINT32 offset = curEip - item.getAddrBegin();
		//REMEMEBER TO LOAD AND UNLOAD SCYLLAWRAPPER!
		scylla_wrapper->loadScyllaLibary();
		scylla_wrapper->ScyllaWrapAddSection(widecstr, ".heap" ,size_write_set , offset , Buffer);
		scylla_wrapper->unloadScyllaLibrary();
		free(Buffer);
	}

	return 0;
}

UINT32 OepFinder::saveHeapZones(std::vector<HeapZone> hzs){

	std::string heaps_dir = Config::getInstance()->getWorkingDir() + "\\heaps";
	_mkdir(heaps_dir.c_str()); // create the folder we will store the .bin of the heap zones 

	HeapZone hz;
	unsigned int hz_begin;
	unsigned int hz_size;
	unsigned char *hz_data;
	Config *config = Config::getInstance();

	std::string heap_map_path = heaps_dir + "\\" +  "heap_map.txt";
	std::ofstream heap_map_file(heap_map_path);

	for(unsigned int i=0;i<hzs.size();i++ ){
		
		std::string heap_bin_path = heaps_dir + "\\" +  "heap_" + std::to_string((_ULonglong)i) + ".bin";

		hz = hzs.at(i);
		hz_begin = hz.begin;
		hz_size  = hz.size;

		// record the location information of this heapzone inside the heap_map.txt 			
		heap_map_file << "heap_" << std::to_string((_ULonglong)i) << " " << std::hex << hz_begin << " " << std::to_string((_ULonglong)hz_size) << " " << "\n" ;
			
		hz_data = (unsigned char *)malloc(hz_size);
		PIN_SafeCopy(hz_data , (void const *)hz_begin , hz_size);
		std::ofstream heap_file(heap_bin_path, std::ios::binary);

		heap_file.write((char *) hz_data, hz_size);
		heap_file.close();
	}
	heap_map_file.close();


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
	ProcInfo *pInfo = ProcInfo::getInstance();
	std::vector<HeapZone> hzs = pInfo->getHeapMap();
	
	// if the curEip is in an heap zones let's save it inside the PE dumped 
	checkHeapWxorX(item, curEip,dumpAndFixResult);

	// In any case if there are any heap-zones let's save them in a separate folder
	if(hzs.size() > 0){
		saveHeapZones(hzs);
	}

	//write the heuristic results on report 
	Config::getInstance()->writeOnReport(curEip, item);
	return OEPFINDER_HEURISTIC_FAIL;
}

UINT32 OepFinder::DumpAndFixIAT(ADDRINT curEip){
	//Getting Current process PID and Base Address
	UINT32 pid = W::GetCurrentProcessId();
	Config * config = Config::getInstance();
	string outputFile = config->getCurrentDumpFilePath();
	string tmpDump = outputFile;
	//std::wstring tmpDump_w = std::wstring(tmpDump.begin(), tmpDump.end());
	string plugin_full_path = config->PLUGIN_FULL_PATH;	
	MYINFO("Calling scylla with : Current PID %d, Current output file dump %s, Plugin %d",pid, outputFile.c_str(), config->PLUGIN_FULL_PATH.c_str());
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
