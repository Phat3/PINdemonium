#include "OepFinder.h"
#include "Debug.h"
namespace W {
    #include <windows.h>
}


OepFinder::OepFinder(void){
	
}


OepFinder::~OepFinder(void){
}


VOID handleWrite(ADDRINT ip, ADDRINT endAddr, UINT32 size)
{		
	FilterHandler *filterHandler = FilterHandler::getInstance();
	MYLOG("Examining Write instruction %x endaddr %x  isFilteredWrite Write %d\n",ip,endAddr, filterHandler->isFilteredWrite(endAddr));	
	/*	if(!filterHandler->isFilteredWrite(endAddr)){	
			
			WxorXHandler wxorxHandler=WxorXHandler::getInstance();
			wxorxHandler.writeSetManager(ip,endAddr,size);
		}*/
	
	

}

UINT32 OepFinder::IsCurrentInOEP(INS ins){
	WxorXHandler wxorxHandler=WxorXHandler::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();

	//W::Sleep(1);
	UINT32 writeItemIndex=-1;
	ADDRINT curEip = INS_Address(ins);
	

	//Tracking Write instructions
	if(wxorxHandler.isWriteINS(ins)){	
			//Filter instructions which write to the stack 
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);	
	}

	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(filterHandler->isLibraryInstruction(curEip)){
		return OEPFINDER_INS_FILTERED; 
	}
	filterHandler->showFilteredLibs();
	MYINFO("Examining if WxorX %x\n",curEip);



	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	writeItemIndex = wxorxHandler.getWxorXindex(ins);

	if(writeItemIndex != -1 ){
			
		BOOL isOEP = heuristics(ins,writeItemIndex);
		wxorxHandler.deleteWriteItem(writeItemIndex);
			
		if(isOEP){
			return OEPFINDER_FOUND_OEP;
		}
		return OEPFINDER_HEURISTIC_FAIL;
	}
	return OEPFINDER_NOT_WXORX_INST;

}






BOOL OepFinder::heuristics(INS ins,UINT32 WriteItemIndex){
	return FALSE;
}
