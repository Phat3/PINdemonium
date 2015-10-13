#include "OepFinder.h"

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

	int writeItemIndex=-1;

	BOOL checkWxorX = TRUE;

	ADDRINT curEip = INS_Address(ins);

	BOOL isLib = filterLib(curEip);

	if(isLib){
	  return INLIB; // we are inside a library
	}

	if(isWriteINS(ins)){
		handleWrite(ins);
	}

	//Return the index of the WriteItem in which the EIP is
	// if it isn't a WxorX instruction return -1
	writeItemIndex = getWxorXindex(ins);

	if(writeItemIndex != -1 ){
			
		BOOL isOEP = heuristics(ins,writeItemIndex);
		deleteWriteItem(writeItemIndex);
			
		if(isOEP){
			return FOUND_OEP;
		}
		return NOT_FOUND_OEP;
	}

}


BOOL OepFinder::checkEIPInWriteitem(ADDRINT curEip , int wiIndex){
return FALSE;
}

BOOL OepFinder::deleteWriteItem(int writeItemIndex){
	return FALSE;
}


BOOL OepFinder::filterLib(ADDRINT eip){
return FALSE;
}

BOOL OepFinder::isWriteINS(INS ins){
return FALSE;
}

BOOL OepFinder::handleWrite(INS ins){

return FALSE;
}

int OepFinder::getWxorXindex(INS ins){
return 1;
}

BOOL OepFinder::heuristics(INS ins,int WriteItemIndex){
return FALSE;
}
