#include "OepFinder.h"
#include "Debug.h"
namespace W {
    #include <windows.h>
}


OepFinder::OepFinder(void){
	
}


OepFinder::~OepFinder(void){
}


VOID handleWrite(ADDRINT ip, ADDRINT startAddr, UINT32 size)
{
	WxorXHandler wxorxHandler=WxorXHandler::getInstance();
	wxorxHandler.writeSetManager(ip,startAddr,size);

}

UINT32 OepFinder::IsCurrentInOEP(INS ins){
	WxorXHandler wxorxHandler=WxorXHandler::getInstance();

	//W::Sleep(1);
	UINT32 writeItemIndex=-1;
	ADDRINT curEip = INS_Address(ins);
	
	//check if current instruction is inside a library
	BOOL isLib = libHandler.filterLib(curEip);
	if(isLib){

		return INLIB; 
	}


	//check if current instruction is a write
	if(wxorxHandler.isWriteINS(ins)){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	}

	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	writeItemIndex = wxorxHandler.getWxorXindex(ins);

	if(writeItemIndex != -1 ){
			
		WriteInterval wi;


		UINT32 isOEP_Witem = heuristics.callWitemHeuristics(ins,wi);
		UINT32 isOEP_Image = heuristics.callImageHeuristics();

		wxorxHandler.deleteWriteItem(writeItemIndex);
			
		if(isOEP_Witem && isOEP_Image){
			return FOUND_OEP;
		}
		return NOT_FOUND_OEP;
	}
	return NOT_WXORX_INST;

}



