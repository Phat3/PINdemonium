#include "ToolHider.h"

ToolHider::ToolHider(void)
{

}


ToolHider::~ToolHider(void)
{
}


ADDRINT handleRead (ADDRINT eip, ADDRINT read_addr,void *fakeMemH){
	//MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
	FakeMemoryHandler fakeMem = *(FakeMemoryHandler *)fakeMemH;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fakeAddr = fakeMem.getFakeMemory(read_addr);

	if(fakeAddr==NULL){

		MYINFO("xxxxxxxxxxxxxx %08x reading %08x",eip,read_addr);
	
	}
	return fakeAddr;
}


void ToolHider::avoidEvasion(INS ins){

   ADDRINT curEip = INS_Address(ins);
   ProcInfo *pInfo = ProcInfo::getInstance();

	//Filter instructions inside a known library
//	if(pInfo->isKnownLibraryInstruction(curEip)){
//		return;
//	}

	// 1 - single instruction detection
	if(this->evasionPatcher.patchDispatcher(ins, curEip)){
		MYINFO("Returned\n");
		return;
	}
	
	// 2 - memory fingerprinting
	// Checking if there is a read at addresses that the application shouldn't be aware of
	for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
		if (INS_MemoryOperandIsRead(ins,op)) {
			//if first read initialize the FakeMemoryHandler
			if(firstRead == 0){
				fakeMemH.initFakeMemory();
				firstRead=1;
			}
		
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleRead,IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_PTR,&fakeMemH, IARG_RETURN_REGS, REG_INST_G0+op, IARG_END);
				INS_RewriteMemoryOperand(ins, op, REG(REG_INST_G0+op));
			
		}
    }
		

	
}
