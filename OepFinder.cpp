#include "OepFinder.h"
#include "Debug.h"
namespace W {
    #include <windows.h>
}

/*
WriteItem p;
p.checked=FALSE;
p.StartAddress=(ADDRINT)5;
p.EndAddress=(ADDRINT)4;

WritesSet.push_back(p);
*/

OepFinder::OepFinder(void){
}


OepFinder::~OepFinder(void){
}


int OepFinder::IsCurrentInOEP(INS ins){

	//W::Sleep(1);
	int writeItemIndex=-1;
	ADDRINT curEip = INS_Address(ins);
	
	//check if current instruction is inside a library
	BOOL isLib = libHandler.filterLib(curEip);
	if(isLib){

		return INLIB; 
	}


	//check if current instruction is a write
	if(wxorxHandler.isWriteINS(ins)){
		wxorxHandler.handleWrite(ins);
	}

	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	writeItemIndex = wxorxHandler.getWxorXindex(ins);

	if(writeItemIndex != -1 ){
			
		BOOL isOEP = heuristics(ins,writeItemIndex);
		wxorxHandler.deleteWriteItem(writeItemIndex);
			
		if(isOEP){
			return FOUND_OEP;
		}
		return NOT_FOUND_OEP;
	}
	return NOT_WXORX_INST;

}






BOOL OepFinder::heuristics(INS ins,int WriteItemIndex){
	return FALSE;
}
