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
	//	MYLOG("Examining Write instruction: %x Targetaddr: %x  \n",ip,end_addr);
		WxorXHandler *wxorxHandler=WxorXHandler::getInstance();
		wxorxHandler->writeSetManager(ip, end_addr, size);
	}
}


/*
Save the initial registers inside the struct
You can fine the macro fo the registers at:
https://software.intel.com/sites/landingpage/pintool/docs/49306/Pin/html/group__REG__CPU__IA32.html
*/
VOID getInitialRegisters(CONTEXT * ctx){
	ProcInfo *proc_info = ProcInfo::getInstance();
	proc_info->setStartRegContext(ctx);	
	proc_info->PrintStartContext();
}


UINT32 OepFinder::IsCurrentInOEP(INS ins){
   	
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();

	ProcInfo *proc_info = ProcInfo::getInstance();

	UINT32 writeItemIndex=-1;
	ADDRINT curEip = INS_Address(ins);
	
	//if it is the first instruction executed from the binary
	if(curEip == proc_info->getFirstINSaddress()){
	   //save the registers 
	   INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)getInitialRegisters , IARG_CONTEXT,IARG_END);
	}

	//check if current instruction is a write
	if(wxorxHandler->isWriteINS(ins)){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	}

	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(filterHandler->isLibraryInstruction(curEip)){
		return OEPFINDER_INS_FILTERED; 
	}

	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	writeItemIndex = wxorxHandler->getWxorXindex(curEip);

	if(writeItemIndex != -1 ){

		WriteInterval item = wxorxHandler->getWritesSet().at(writeItemIndex);
		//DEBUG
		MYLOG("[W xor X BROKEN!] IP : %08x  BEGIN : %08x  END : %08x", curEip, item.getAddrBegin(), item.getAddrEnd());

		ADDRINT prev_ip = proc_info->getPrevIp();
		//call the proper heuristics
		UINT32 isOEP_Witem = Heuristics::longJmpHeuristic(ins, prev_ip);
		UINT32 isOEP_Image = Heuristics::entropyHeuristic();
		UINT32 isOEP_JMP = Heuristics::jmpOuterSectionHeuristic(ins, prev_ip);

		//delete the WriteInterval just analyzed
		wxorxHandler->deleteWriteItem(writeItemIndex);

		//DEBUG
	    //update the prevuious IP
		proc_info->setPrevIp(INS_Address(ins));

		if(isOEP_Witem && isOEP_Image){
			return OEPFINDER_FOUND_OEP;
		}	
		return OEPFINDER_HEURISTIC_FAIL;

	}
	//update the previous IP
	proc_info->setPrevIp(INS_Address(ins));
	return OEPFINDER_NOT_WXORX_INST;


}



