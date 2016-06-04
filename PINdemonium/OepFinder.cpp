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

void check_heap_zone_deps(unsigned char *buffer_pointer, unsigned char *end_buffer , UINT32 current_write_item_index , std::set<UINT32> checked_heap_zone , std::vector<UINT32> to_check_heap_zone ){

	ProcInfo *proc_info = ProcInfo::getInstance();	
	WxorXHandler *wxorxH = WxorXHandler::getInstance();
	
	checked_heap_zone.insert(current_write_item_index); // adding to the checked zone the current heap zone under analysis

	unsigned int memops; 

	// initialize the XED tables -- one time.
	xed_tables_init();

	// The state of the machine -- required for decoding
	xed_state_t dstate;
	xed_state_zero(&dstate);
	xed_state_init(&dstate,
					XED_MACHINE_MODE_LEGACY_32, 
					XED_ADDRESS_WIDTH_32b, 
					XED_ADDRESS_WIDTH_32b);

	// create the decoded instruction, and fill in the machine mode (dstate)
	xed_decoded_inst_t xedd;
	xed_operand_values_t *ins_ops;
	xed_iclass_enum_t ins_class;
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	// max number of bytes per instruction 
	unsigned int bytes = 16; 
	unsigned int noperands;
	// set the starting address of the instructions to disassemble 
	xed_error_enum_t xed_error;

	xed_bool_t xed_okay;
	char myBuffer[1024];

	do{	
		// decode the instruction 
		xed_error = xed_decode(&xedd,buffer_pointer,bytes);	
		xed_okay = (xed_error == XED_ERROR_NONE); // checking errors  ( TO FIX ) 
		xed_decoded_inst_dump(&xedd,myBuffer,sizeof(myBuffer)); // dump the instructions inside the myBuffer
		ins_class = xed_decoded_inst_get_iclass(&xedd);
		const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);


		printf("\nINSTRUCTION DECODED: %s\n", myBuffer);
		
		buffer_pointer = buffer_pointer + xedd._decoded_length; // move the buffer pointer of the length of decode instruction 

		// Let's check immediately if this is a control flow redirection instruction and if the destination is inside this heap zone or not
		if(ins_class == XED_ICLASS_CALL_FAR ||  ins_class == XED_ICLASS_CALL_FAR || ins_class == XED_ICLASS_JMP ){

			noperands = xed_inst_noperands(xi);
			
			for(int i=0; i < noperands ; i++) { 
				const xed_operand_t* op = xed_inst_operand(xi,i);
				xed_operand_enum_t op_name = xed_operand_name(op);
				printf("operand name : %s\n" , xed_operand_enum_t2str(op_name) );

				switch(op_name){
					        case XED_OPERAND_REG0:
							case XED_OPERAND_REG1:
							case XED_OPERAND_REG2:
							case XED_OPERAND_REG3:
							case XED_OPERAND_REG4:
							case XED_OPERAND_REG5:
							case XED_OPERAND_REG6:
							case XED_OPERAND_REG7:
							case XED_OPERAND_REG8:
							case XED_OPERAND_BASE0:
							case XED_OPERAND_BASE1:{
													  xed_reg_enum_t r = xed_decoded_inst_get_reg(&xedd, op_name);
													  printf("REG is %s\n" ,
														 xed_reg_enum_t2str(r));
													  break;
												   }
							}
			}
		} 

		memops = xed_decoded_inst_number_of_memory_operands(&xedd);
		
		noperands = xed_inst_noperands(xi); // get the number of operands of the instruction

		unsigned int i, memops = xed_decoded_inst_number_of_memory_operands(&xedd);
		
		// TO TEST if it is needed more tuning in order to understand if there are any addresses ouf of this heap zone

		for( i=0;i<memops; i++){
			if (xed_operand_values_has_memory_displacement(&xedd))
			{
				xed_uint_t disp_bits = xed_decoded_inst_get_memory_displacement_width(&xedd,i);
				if (disp_bits)
				{
					UINT32 mem_disp = xed_decoded_inst_get_memory_displacement(&xedd,i);
					
					//printf("Displacement: %08x\n" , mem_disp);

					UINT32 writeItemIndex = wxorxH->getWxorXindex(mem_disp); // check of the displacement is inside another heap_zone 

					if(writeItemIndex != -1  && writeItemIndex != current_write_item_index){ // if we have a reference in ANOTHER heap zone 
						
						proc_info->addHeapDependence(current_write_item_index,writeItemIndex,xedd);

						if(ins_class == XED_ICLASS_CALL_FAR ||  ins_class == XED_ICLASS_CALL_FAR || ins_class == XED_ICLASS_JMP ){
							to_check_heap_zone.push_back(writeItemIndex); // push this heap zone in the to_check_list if it is a control flow redirection dependency
							printf("JMP Displacement: %08x\n" , mem_disp);
						} 
						else{
							printf("Read/Write Displacement: %08x\n", mem_disp);
						}

						// TODO:
						// Need to insert the new heap zone in the final dump 
						// Need to patch this call
						// Need to analyze this new heap zone in order to search for other cross dependencies? 
					}
					else
						if(writeItemIndex != -1  && writeItemIndex == current_write_item_index){ // we have a reference inside THIS heap zone 
							   proc_info->addHeapDependence(current_write_item_index,current_write_item_index,xedd);							
							// TODO: 
							// Need only to patch this reference with the static address of the newly added section 
						}
				}
		    }
		}

	  xed_decoded_inst_zero_set_mode(&xedd, &dstate); // set the xedd variable to zero and let's go to the next instruction
  }while(buffer_pointer < end_buffer);

  // --- Here we have finished to analyze all the instructions inside the  curr_heapzone ---

}

void check_heap_interdependencies(unsigned char *buffer_pointer, UINT32 size_starting_write_set , UINT32 starting_write_set_item_index){

	std::set<UINT32> checked_heap_zone;  // keeping track of the already checked heap zone 
										 // this is not a set since we don't need the search, but we are using it basically as a stack

	std::vector<UINT32> to_check_heap_zone; // keeping track of the heap zone to check discovered during the analysis
											// this is a set since the search inside this is O(LogN)

	//checked_heap_zone.insert(current_write_item_index); // adding to the checked zone the current heap zone under analysis

	to_check_heap_zone.push_back(starting_write_set_item_index);  // initialize the to_check_heap_zone with the current_write_item

	/*
	unsigned char * end_buffer = buffer_pointer + size_starting_write_set;
	UINT32 current_write_item_index = starting_write_set_item_index;

	check_heap_zone_deps(buffer_pointer,end_buffer, current_write_item_index,checked_heap_zone,to_check_heap_zone);

	*/

  // --- Now let's see if there are any other heap zones to analyze ----
		WxorXHandler *wxorxH = WxorXHandler::getInstance();

  UINT32 to_check_index = -1;

  do{
    if(!to_check_heap_zone.empty()){ // if there are any other heap_zone to check 
		to_check_index = to_check_heap_zone.back();
		to_check_heap_zone.pop_back();
	
		if(checked_heap_zone.find(to_check_index) != checked_heap_zone.end()){
		   // the heap zone index is included inside the heap zones already checked, skip it and go to next.
			to_check_index = -1; // reset to -1 the index 
		}
		else{
   		    // the heap zone index isn't included inside the checked heap_zone and must be analyzed!
				unsigned char * end_buffer = buffer_pointer + size_starting_write_set;

		    check_heap_zone_deps(buffer_pointer,end_buffer, to_check_index ,checked_heap_zone,to_check_heap_zone);
			printf("EXITING\n");
			exit(0);
			
		}	
	}
	else{
		// We have finished to analyze heap zones! 
		to_check_index = -2; 
	}
  }while(to_check_index == -1);

  if(to_check_index == -2 ){
	return;
  }
  else{
	  WriteInterval item = wxorxH->getWritesSet()[to_check_index];
	  UINT32 size_write_set = item.getAddrEnd() - item.getAddrBegin();
	  //prepare the buffer to copy inside the stuff into the heap section to dump 		  
	  unsigned char *Buffer = (unsigned char *)malloc( size_write_set );
	  // copy the heap zone into the buffer 
	  PIN_SafeCopy(Buffer , (void const *)item.getAddrBegin() , size_write_set);	
	  //check_heap_zone_deps(
  }

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
			this->analysis(item, writeItemIndex, ins, prev_ip, curEip,result);
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
			this->analysis(item, writeItemIndex, ins, prev_ip, curEip , result);
			wxorxH->incrementCurrJMPNumber(writeItemIndex);
			config->incrementDumpNumber(); //Incrementing the dump number even if Scylla is not successful
		}				
	}
}

BOOL OepFinder::analysis(WriteInterval item, UINT32 write_item_index , INS ins, ADDRINT prev_ip, ADDRINT curEip , int dumpAndFixResult){
	//call the proper heuristics
	//we have to implement it in a better way!!
	item.setLongJmpFlag(Heuristics::longJmpHeuristic(ins, prev_ip));
	item.setEntropyFlag(Heuristics::entropyHeuristic());
	item.setJmpOuterSectionFlag(Heuristics::jmpOuterSectionHeuristic(ins, prev_ip));
	item.setPushadPopadFlag(Heuristics::pushadPopadHeuristic());
	MYINFO("CURRENT WRITE SET SIZE : %d\t START : %08x\t END : %08x\t FLAG : %d", (item.getAddrEnd() - item.getAddrBegin()), item.getAddrBegin(), item.getAddrEnd(), item.getBrokenFlag());
	UINT32 error = Heuristics::initFunctionCallHeuristic(curEip,&item);

	if( item.getHeapFlag() && dumpAndFixResult != SCYLLA_ERROR_FILE_FROM_PID  && dumpAndFixResult != SCYLLA_ERROR_DUMP ){
		MYINFO("-----DUMPING HEAP-----\n");
		unsigned char * Buffer;
		UINT32 size_write_set = item.getAddrEnd() - item.getAddrBegin();
		//prepare the buffer to copy inside the stuff into the heap section to dump 		  
		Buffer = (unsigned char *)malloc( size_write_set );
		// copy the heap zone into the buffer 
		PIN_SafeCopy(Buffer , (void const *)item.getAddrBegin() , size_write_set);	

		//***********************************************************************************************************
		// Here the buffer must be analyzed in order to understand if there are cross dependencies between heap zones
		//***********************************************************************************************************

		UINT32 disassembly_start = curEip - item.getAddrBegin(); // this in order to start disassemble exactly where the program jumps
																 // offset between the start of the item and the curEip 

		unsigned char *buffer_pointer = (unsigned char * ) Buffer + disassembly_start; // position the buffer pointer exactly at the offset calculated before

		check_heap_interdependencies(buffer_pointer,size_write_set,write_item_index);


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
