#pragma once
#include "OepFinder.h"
#include "Log.h"
#include "ProcInfo.h"

/* Global variable useful in order to store the registers saved in the callback */
RegContext rg;


OepFinder::OepFinder(void){
	
}

OepFinder::~OepFinder(void){
}


VOID handleWrite(ADDRINT ip, ADDRINT end_addr, UINT32 size)
{		
	FilterHandler *filterHandler = FilterHandler::getInstance();

	//check if the target address belongs to some filtered range		
	if(!filterHandler->isFilteredWrite(end_addr,ip)){	
	//	MYINFO("Examining Write instruction: %x Targetaddr: %x  ",ip,end_addr);
		WxorXHandler *wxorxHandler=WxorXHandler::getInstance();
		wxorxHandler->writeSetManager(ip, end_addr, size);
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


UINT32 OepFinder::IsCurrentInOEP(INS ins){
   	
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();

	ProcInfo *proc_info = ProcInfo::getInstance();

	clock_t now = clock();

	if(proc_info->getStartTimer() != -1  && ((double)( now - proc_info->getStartTimer() )/CLOCKS_PER_SEC) > TIME_OUT  ){
		MYINFO("TIMER SCADUTO");
		exit(0);
	}

	UINT32 writeItemIndex=-1;
	ADDRINT curEip = INS_Address(ins);

	//check if current instruction is a write
	if(wxorxHandler->isWriteINS(ins)){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	}

	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(filterHandler->isLibraryInstruction(curEip)){
		return OEPFINDER_INS_FILTERED; 
	}

	this->handlePopadAndPushad(ins);

	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	writeItemIndex = wxorxHandler->getWxorXindex(curEip);

	if(writeItemIndex != -1 ){

		WriteInterval item = wxorxHandler->getWritesSet().at(writeItemIndex);
		//DEBUG
		//MYINFO("[W xor X BROKEN!] IP : %08x  BEGIN : %08x  END : %08x", curEip, item.getAddrBegin(), item.getAddrEnd());	

		//update the start timer 
		proc_info->setStartTimer(clock());
		MYINFO("SETTED TIMER", (double) (proc_info->getStartTimer())/CLOCKS_PER_SEC);
	
		ADDRINT prev_ip = proc_info->getPrevIp();
		//call the proper heuristics
		//we have to implement it in a better way!!
		item.setLongJmpFlag(Heuristics::longJmpHeuristic(ins, prev_ip));
		item.setEntropyFlag(Heuristics::entropyHeuristic());
		item.setJmpOuterSectionFlag(Heuristics::jmpOuterSectionHeuristic(ins, prev_ip));
		item.setPushadPopadFlag(Heuristics::pushadPopadHeuristic());

		Log::getInstance()->writeOnReport(curEip, item);
		//MYINFO("[JSON] {ip : %08x, begin : %08x, end : %08x; entropy_flag : %d, longjmp_flag : %d, jmp_oter_section_flag : %d}", curEip, item.getAddrBegin(), item.getAddrEnd(), isOEP_E, isOEP_LJ, isOEP_JOS);


		//call the proper heuristics
		UINT32 isOEP_Witem = 0;//Heuristics::longJmpHeuristic(ins, prev_ip);
		UINT32 isOEP_Image = 0;//Heuristics::entropyHeuristic();
		//Heuristics::jmpOuterSectionHeuristic(ins, prev_ip);
		Heuristics::initFunctionCallHeuristic(curEip,item);

		//delete the WriteInterval just analyzed
		wxorxHandler->deleteWriteItem(writeItemIndex);


		//DEBUG
	    //update the prevuious IP
		proc_info->setPrevIp(INS_Address(ins));

		return OEPFINDER_HEURISTIC_FAIL;

	}
	//update the previous IP
	proc_info->setPrevIp(INS_Address(ins));
	return OEPFINDER_NOT_WXORX_INST;


}



