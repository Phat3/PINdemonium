#include "WxorXHandler.h"
#include "pin.h"




WxorXHandler::~WxorXHandler(void)
{
}



//----------------------- PUBLIC METHODS -----------------------

BOOL WxorXHandler::isWriteINS(INS ins){
	return INS_IsMemoryWrite(ins);
}

VOID WxorXHandler::writeSetManager(ADDRINT ip, ADDRINT end_addr, UINT32 size){
	printf( "IP : %08x	  write at : %08x		SIZE: %d\n" , ip, end_addr, size);
	//calculate the end address of the write
	UINT32 start_addr = end_addr + size;
	//iterate through our structure in order to find if we have to update one of our WriteInterval
	for(std::vector<WriteInterval>::iterator item = WritesSet.begin(); item != WritesSet.end(); ++item) {
		//if we foud that an item has to be updated then update it and return
		if(item->checkUpdate(start_addr, end_addr)){
			//item->update(startAddr, endAddr);
			//return;
		}
	}
	//otherwise create a new WriteInterval object and add it to our structure
	WriteInterval new_interval(start_addr, end_addr);
	WritesSet.push_back(new_interval);
}

UINT32 WxorXHandler::getWxorXindex(INS ins){
	return 1;
}


BOOL WxorXHandler::deleteWriteItem(UINT32 writeItemIndex){
	return FALSE;
}
