#pragma once
#include "ProcInfo.h"

#define MAX_WRITE_SIZE 16
static ADDRINT fakeWriteAddress;

class FakeWriteHandler
{
public:
	FakeWriteHandler(void);
	~FakeWriteHandler(void);
	ADDRINT getFakeWriteAddress(ADDRINT cur_addr);

private:
	ProcInfo *pInfo;
};

