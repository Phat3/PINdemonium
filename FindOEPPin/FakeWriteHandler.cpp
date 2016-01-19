#include "FakeWriteHandler.h"


FakeWriteHandler::FakeWriteHandler(void)
{
	pInfo = ProcInfo::getInstance();
	fakeWriteAddress = (ADDRINT)malloc(MAX_WRITE_SIZE*sizeof(char));
}


FakeWriteHandler::~FakeWriteHandler(void)
{
}

ADDRINT FakeWriteHandler::getFakeWriteAddress(ADDRINT cur_addr){
	
	if(pInfo->isInsideProtectedSection(cur_addr)){
		MYINFO("Suspicious Write at  %08x",cur_addr);
		return fakeWriteAddress;
	}
	return cur_addr;
	
}
