#include "OepFinder.h"


ADDRINT prev_ip = 0;

OepFinder::OepFinder(void){
	
}

OepFinder::~OepFinder(void){
}


string getSectionName(ADDRINT ip){

	IMG img = IMG_FindByAddress(ip); 
	for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) ){
		ADDRINT begin_addr = SEC_Address(sec);
		ADDRINT end_addr = begin_addr + SEC_Size(sec);
		if(ip >= begin_addr && ip < end_addr){
			return SEC_Name(sec);
		}
	}
	return NULL;
}



VOID handleWrite(ADDRINT ip, ADDRINT end_addr, UINT32 size)
{		
	FilterHandler *filterHandler = FilterHandler::getInstance();
	//check if the target address belongs to some filtered range		
	if(!filterHandler->isFilteredWrite(end_addr)){	
		//MYLOG("Examining Write instruction: %x Targetaddr: %x  \n",ip,end_addr);
		WxorXHandler *wxorxHandler=WxorXHandler::getInstance();
		wxorxHandler->writeSetManager(ip, end_addr, size);
	}
}

UINT32 OepFinder::IsCurrentInOEP(INS ins){
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();

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

	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	writeItemIndex = wxorxHandler->getWxorXindex(curEip);

	if(writeItemIndex != -1 ){

		WriteInterval item = wxorxHandler->getWritesSet().at(writeItemIndex);
		//DEBUG
		MYLOG("[W xor X BROKEN!] IP : %08x  BEGIN : %08x  END : %08x", curEip, item.getAddrBegin(), item.getAddrEnd());

		//delete the WriteInterval just analyzed
		wxorxHandler->deleteWriteItem(writeItemIndex);

		//call the proper heuristics
		UINT32 isOEP_Witem = Heuristics::longJmpHeuristic(ins, prev_ip);;
		UINT32 isOEP_Image = Heuristics::entropyHeuristic();

		//DEBUG
	    //update the prevuious IP
		this->prev_ip = INS_Address(ins);

		if(isOEP_Witem && isOEP_Image){
			return OEPFINDER_FOUND_OEP;
		}	
		return OEPFINDER_HEURISTIC_FAIL;

	}
	//update the previous IP
	this->prev_ip = INS_Address(ins);
	return OEPFINDER_NOT_WXORX_INST;

}



