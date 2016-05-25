#include "FakeWriteHandler.h"


FakeWriteHandler::FakeWriteHandler(void)
{
	pInfo = ProcInfo::getInstance();	
}


FakeWriteHandler::~FakeWriteHandler(void)
{
}

//hijack the write operation
ADDRINT FakeWriteHandler::getFakeWriteAddress(ADDRINT cur_addr){	
	if(pInfo->isInsideProtectedSection(cur_addr)){
		MYINFO("Suspicious Write at  %08x",cur_addr);
		fakeWriteAddress = (ADDRINT)malloc(MAX_WRITE_SIZE*sizeof(char));
		return fakeWriteAddress;
	}
	return cur_addr;	
}
