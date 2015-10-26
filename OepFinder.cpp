#include "OepFinder.h"

/* Global variable useful in order to store the registers saved in the callback */
RegContext rg;


OepFinder::OepFinder(void){
	
}

OepFinder::~OepFinder(void){
}

//update the write set manager
VOID handleWrite(ADDRINT ip, ADDRINT end_addr, UINT32 size){	

	FilterHandler *filterHandler = FilterHandler::getInstance();
	//check if the target address belongs to some filtered range		
	if(!filterHandler->isFilteredWrite(end_addr,ip)){
		//if not update the write set
		WxorXHandler::getInstance()->writeSetManager(ip, end_addr, size);
	}

}



//Save the initial registers inside the struct
//You can fine the macro fo the registers at:
//https://software.intel.com/sites/landingpage/pintool/docs/49306/Pin/html/group__REG__CPU__IA32.html
VOID getInitialRegisters(CONTEXT * ctx){
	ProcInfo *proc_info = ProcInfo::getInstance();
	proc_info->setStartRegContext(ctx);	
	proc_info->PrintStartContext();
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

// - Check if the current instruction is a write  ----> add the instrumentation routine that register the write informations
// - Chek if the current instruction belongs to a library  -----> return
// - Chek if the current instruction is a popad or a pushad  -----> update the flag in ProcInfo
// - Check if the current instruction broke the W xor X law  -----> trigger the heuristics and write the report
// - Set the previous ip to the current ip ( useful for some heuristics like jumpOuterSection )
UINT32 OepFinder::IsCurrentInOEP(INS ins){
   	
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();
	ProcInfo *proc_info = ProcInfo::getInstance();
	UINT32 writeItemIndex=-1;
	ADDRINT curEip = INS_Address(ins);
	//if it is the first instruction executed from the binary
	/*
	if(curEip == proc_info->getFirstINSaddress()){
	   //save the registers 
	   INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)getInitialRegisters , IARG_CONTEXT,IARG_END);
	}
	*/
	//check if current instruction is a write
	if(wxorxHandler->isWriteINS(ins)){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	}
	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(filterHandler->isLibraryInstruction(curEip)){
		return OEPFINDER_INS_FILTERED; 
	}
	//check if the current instruction is a popad or a pushad
	this->handlePopadAndPushad(ins);
	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	writeItemIndex = wxorxHandler->getWxorXindex(curEip);
	//W xor X broken
	if(writeItemIndex != -1 ){
		WriteInterval item = wxorxHandler->getWritesSet().at(writeItemIndex);
		ADDRINT prev_ip = proc_info->getPrevIp();
		//call the proper heuristics
		//we have to implement it in a better way!!
		item.setLongJmpFlag(Heuristics::longJmpHeuristic(ins, prev_ip));
		item.setEntropyFlag(Heuristics::entropyHeuristic());
		item.setJmpOuterSectionFlag(Heuristics::jmpOuterSectionHeuristic(ins, prev_ip));
		item.setPushadPopadFlag(Heuristics::pushadPopadHeuristic());
		Heuristics::initFunctionCallHeuristic(curEip,item);
		//write the heuristic resuòts on ile
		Log::getInstance()->writeOnReport(curEip, item);
		//delete the WriteInterval just analyzed
		wxorxHandler->deleteWriteItem(writeItemIndex);
	    //update the prevuious IP
		proc_info->setPrevIp(INS_Address(ins));
		return OEPFINDER_HEURISTIC_FAIL;
	}
	//update the previous IP
	proc_info->setPrevIp(INS_Address(ins));
	return OEPFINDER_NOT_WXORX_INST;

}