#include "OepFinder.h"


OepFinder::OepFinder(void){
	this->wxorxHandler = WxorXHandler::getInstance();
	this->report = Report::getInstance();
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
		//not the first broken in this write set		
		if(item->getBrokenFlag()){
			//if INTER_WRITESET_ANALYSIS_ENABLE flag is enable check if inter section JMP and trigger analysis
			Config *config = Config::getInstance();
			if(config->INTER_WRITESET_ANALYSIS_ENABLE == true){ 				
				interWriteSetJMPAnalysis(curEip,prev_ip,ins,item );
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
			Config::getInstance()->setNewWorkingDirectory(); // create the folder dump_0 inside the folder associated to this timestamp 
			report->createReportDump(curEip,item->getAddrBegin(),item->getAddrEnd(),Config::getInstance()->getDumpNumber(),false);
			int result = this->DumpAndFixIAT(curEip);
			Config::getInstance()->setWorking(result);
			MYPRINT("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
			MYPRINT("- - - - - - - - - - - - - - - - - - - - - STAGE 2: ANALYZING DUMP - - - - - - - - - - - - - - - - - - - - - -");
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


void OepFinder::interWriteSetJMPAnalysis(ADDRINT curEip,ADDRINT prev_ip,INS ins, WriteInterval *item){	
	WxorXHandler *wxorxH = WxorXHandler::getInstance();
	ProcInfo *pInfo = ProcInfo::getInstance();
	Config *config = Config::getInstance();
	//long jump detected intra-writeset ---> trigger analysis and dump
	UINT32 currJMPLength = std::abs( (int)curEip - (int)prev_ip);
	if( currJMPLength > item->getThreshold()){
		//Check if the current WriteSet has already dumped more than WRITEINTERVAL_MAX_NUMBER_JMP times
		//and check if the previous instruction was in the library (Long jump because return from Library)
		if(item->getCurrNumberJMP() < config->WRITEINTERVAL_MAX_NUMBER_JMP  && !pInfo->isLibraryInstruction(prev_ip)){
			//Try to dump and Fix the IAT if successful trigger the analysis
			MYPRINT("\n\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
			MYPRINT("- - - - - - - - - - - - - - JUMP NUMBER %d OF LENGHT %d  IN STUB FROM %08x TO %08x- - - - - - - - - - - - - -\n",item->getCurrNumberJMP(),currJMPLength, item->getAddrBegin(),item->getAddrEnd());
			MYINFO("Current EIP %08x",curEip);
			report->createReportDump(curEip,item->getAddrBegin(),item->getAddrEnd(),Config::getInstance()->getDumpNumber(),true);
			Config::getInstance()->setNewWorkingDirectory(); // create a new folder to store the dump 
			int result = this->DumpAndFixIAT(curEip);
			config->setWorking(result);
			this->analysis(item, ins, prev_ip, curEip , result);
			report->closeReportDump(); //close the current dump report
			item->incrementCurrNumberJMP();
			config->incrementDumpNumber(); //Incrementing the dump number even if Scylla is not successful
		}				
	}
}

UINT32 OepFinder::checkHeapWxorX(WriteInterval* item, ADDRINT curEip, int dumpAndFixResult){

		// include in the PE the dump of the current heap zone in which we have break the WxorX 
	if( item->getHeapFlag() && dumpAndFixResult != SCYLLA_ERROR_FILE_FROM_PID  && dumpAndFixResult != SCYLLA_ERROR_DUMP ){
		MYPRINT("[INFO][OepFinder.cpp] - EIP ON THE HEAP - DUMPING THE HEAP-ZONE BEGIN 0x%08x | END 0x%08x", item->getAddrBegin(),item->getAddrEnd());
		unsigned char * Buffer;
		UINT32 size_write_set = item->getAddrEnd() - item->getAddrBegin();
		//prepare the buffer to copy inside the stuff into the heap section to dump 		  
		Buffer = (unsigned char *)malloc( size_write_set );
		// copy the heap zone into the buffer 
		PIN_SafeCopy(Buffer , (void const *)item->getAddrBegin() , size_write_set);	
		ScyllaWrapperInterface *scylla_wrapper = ScyllaWrapperInterface::getInstance();
		// get the name of the last dump from the Config object 
		Config *config = Config::getInstance();
		string dump_path = config->getCurrentDumpFilePath();

		if(dumpAndFixResult != 0){
			dump_path = dump_path + "_dmp";
		}

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
		UINT32 offset = curEip - item->getAddrBegin();
		//REMEMEBER TO LOAD AND UNLOAD SCYLLAWRAPPER!
		scylla_wrapper->loadScyllaLibary();
		scylla_wrapper->ScyllaWrapAddSection(widecstr, ".heap" ,size_write_set , offset , Buffer);
		scylla_wrapper->unloadScyllaLibrary();
		free(Buffer);
	}
	else{
	  MYPRINT("[INFO][OepFinder.cpp] - [WARN] EIP IS NOT ON THE HEAP\n");
	}

	return 0;
}


std::string dumpHZ(HeapZone hz, char * data, std::string hz_md5){

	std::string heap_dir_path = Config::getInstance()->getHeapDir();
	std::string heap_bin_name = "heap_" + hz_md5 + ".bin";
	std::string heap_bin_path = heap_dir_path + "\\" + heap_bin_name; // this is the heap.bin in the global folder HEAP

	// dump of the heap inside this folder 
	std::string heap_dir = Config::getInstance()->getHeapDir();
	std::ofstream heap_file(heap_bin_path, std::ios::binary);

	heap_file.write((char *) data, hz.size);
	heap_file.close();

	return heap_bin_path;
}


std::string linkHZ(std::string heap_bin_path){

	// we will save the link to the heap.bin inside the folder heaps of the currente dump 
	std::string heaps_dir = Config::getInstance()->getWorkingDir() + "\\heaps";

	// creating the name of the link by extracting the name of the heap.bin 
	std::size_t pos = heap_bin_path.find("heap_");
	std::string heap_link_name = heap_bin_path.substr(pos);

	// finally composing the heap link path
	std::string heap_link_path = heaps_dir + "\\" + heap_link_name;

	W::CreateHardLink(heap_link_path.c_str() , heap_bin_path.c_str() ,NULL);

	return  heap_link_name;
}

void logHZ(std::string heap_link_name, HeapZone hz, std::string hz_md5){

	// open the heap_map.txt
	std::string working_dir = Config::getInstance()->getWorkingDir();  
	std::string heap_map_path = working_dir + "\\heaps" +  "\\heap_map.txt"; // write the log 

	//printf("Inside logHZ - heap_map_path: %s\n", heap_map_path.c_str());

	std::ofstream heap_map_file(heap_map_path,ios::app);

	heap_map_file << heap_link_name << " " << std::hex << hz.begin << " " << std::to_string((_ULonglong)hz.size) << " " << "\n" ;

	heap_map_file.close();
}



VOID OepFinder::saveHeapZones(std::map<std::string,HeapZone> hzs, std::map<std::string,std::string> hzs_dumped){

	MYPRINT("[INFO][OepFinder.cpp] - SAVING ALL THE HEAP-ZONES ALLOCATED UNTIL NOW: %d HEAP-ZONES\n", hzs.size());
	std::string heaps_dir = Config::getInstance()->getWorkingDir() + "\\heaps";
	_mkdir(heaps_dir.c_str()); // create the folder we will store the .bin of the heap zones 

	char *hz_data;
	std::string hz_md5;
	std::string hz_md5_now;
	Config *config = Config::getInstance();

	std::string heap_map_path = heaps_dir + "\\" +  "heap_map.txt";
	std::ofstream heap_map_file(heap_map_path);

	for (std::map<std::string,HeapZone>::iterator it=hzs.begin(); it!=hzs.end(); ++it){	
		HeapZone hz = it->second;
		std::string mem_hz_md5 = it->first;
		hz_data = (char *)malloc(hz.size);
		PIN_SafeCopy(hz_data , (void const *)hz.begin , hz.size);
		hz_md5_now = md5(hz_data); // take the md5 of the data inside the heap 

		std::map<std::string,std::string>::iterator hz_dumped_it = hzs_dumped.find(hz_md5_now);

		if(hz_dumped_it != hzs_dumped.end()){
			// an heapzone with these data has already been dumped
			MYPRINT("HEAPZONE [POSITION (BEGIN 0x%08x | END 0x%08x) - DATA MD5 %s] ALREADY DUMPED! - CREATING HARD LINKS", hz.begin,hz.end, hz_md5_now.c_str());
			std::string heap_link_name = linkHZ(hz_dumped_it->second);
			logHZ(heap_link_name,hz,hz_md5);
		}else{
			MYPRINT("HEAPZONE [POSITION (BEGIN 0x%08x | END 0x%08x) - DATA MD5 %s] TO DUMP! - CREATING DUMP AND HARD LINKS", hz.begin,hz.end, hz_md5_now.c_str());
			std::string heap_bin_path  = dumpHZ(hz,hz_data,hz_md5_now);
			std::string heap_link_name = linkHZ(heap_bin_path);
			logHZ(heap_link_name,hz,hz_md5_now);
			ProcInfo *pInfo = ProcInfo::getInstance();
			pInfo->insertDumpedHeapZone(hz_md5_now,heap_bin_path);
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
 	Heuristics::yaraHeuristic();

	MYINFO("CURRENT WRITE SET SIZE : %d\t START : 0x%08x\t END : 0x%08x\t BROKEN-FLAG : %d", (item->getAddrEnd() - item->getAddrBegin()), item->getAddrBegin(), item->getAddrEnd(), item->getBrokenFlag());
	ProcInfo *pInfo = ProcInfo::getInstance();
	std::map<std::string , HeapZone> hzs = pInfo->getHeapMap();
	std::map<std::string , std::string> hzs_dumped = pInfo->getDumpedHZ();
	
	MYPRINT("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
	MYPRINT("- - - - - - - - - - - - - - - - - - - - - STAGE 3: DUMP HEAP - - - - - - - -- - - - - - - - - - - - - - - - -");
	MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");

	// if the curEip is in an heap zones let's save it inside the PE dumped 
	checkHeapWxorX(item, curEip,dumpAndFixResult);

	// In any case if there are any heap-zones let's save them in a separate folder
	if(hzs.size() > 0){
		saveHeapZones(hzs,hzs_dumped);
	}

	//write the heuristic results on ile
	return OEPFINDER_HEURISTIC_FAIL;
}

UINT32 OepFinder::DumpAndFixIAT(ADDRINT curEip){
	//Getting Current process PID and Base Address
	UINT32 pid = W::GetCurrentProcessId();
	Config * config = Config::getInstance();
	string outputFile = config->getCurrentDumpFilePath();
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

BOOL OepFinder::existFile (std::string name) {
	if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}
