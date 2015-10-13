#include "WxorXHandler.h"
#include "pin.h"


WxorXHandler::WxorXHandler(void)
{
}


WxorXHandler::~WxorXHandler(void)
{
}

//----------------------- PRIVATE METHODS -----------------------

VOID writeSetManager(ADDRINT ip, ADDRINT ea, UINT32 size)
{
	printf( "IP : %08x	  write at : %08x		SIZE: %d\n" , ip, ea, size);
}


//----------------------- PUBLIC METHODS -----------------------

BOOL WxorXHandler::isWriteINS(INS ins){
	return INS_IsMemoryWrite(ins);
}

VOID WxorXHandler::handleWrite(INS ins){
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)writeSetManager, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
}

UINT32 WxorXHandler::getWxorXindex(INS ins){
	return 1;
}


BOOL WxorXHandler::deleteWriteItem(UINT32 writeItemIndex){
	return FALSE;
}
