#include "WxorXHandler.h"
#include "pin.h"




WxorXHandler::~WxorXHandler(void)
{
}

/*
WriteItem p;
p.checked=FALSE;
p.StartAddress=(ADDRINT)5;
p.EndAddress=(ADDRINT)4;

WritesSet.push_back(p);
*/


//----------------------- PUBLIC METHODS -----------------------

BOOL WxorXHandler::isWriteINS(INS ins){
	return INS_IsMemoryWrite(ins);
}

VOID WxorXHandler::writeSetManager(ADDRINT ip, ADDRINT startAddr, UINT32 size){
	//printf( "IP : %08x	  write at : %08x		SIZE: %d\n" , ip, startAddr, size);
	UINT32 endAddr = startAddr + size;
	BOOL newBlock=TRUE;
	for(std::vector<WriteItem>::iterator it = WritesSet.begin(); it != WritesSet.end(); ++it) {
		
		/* std::cout << *it; ... */
	}
	//
	if(newBlock){
		WriteItem p;
		p.checked=FALSE;
		p.StartAddress=startAddr;
		p.EndAddress=endAddr;
		WritesSet.push_back(p);
	}
}

UINT32 WxorXHandler::getWxorXindex(INS ins){
	return 1;
}


BOOL WxorXHandler::deleteWriteItem(UINT32 writeItemIndex){
	return FALSE;
}
