#include "ToolHider.h"
#include <regex>


ToolHider::ToolHider(void)
{
	
}


ToolHider::~ToolHider(void)
{
}


ADDRINT handleRead(ADDRINT eip, ADDRINT read_addr,void *fake_mem_h){
	
	//MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
	FakeMemoryHandler fake_mem = *(FakeMemoryHandler *)fake_mem_h;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fake_addr = fake_mem.getFakeMemory(read_addr, eip);

	if(fake_addr==NULL){

		MYINFO("xxxxxxxxxxxxxx %08x in %s reading %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr);
	}

	if (fake_addr != read_addr){
		MYINFO("ip : %08x in %s reading %08x and it has been redirected to : %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr, fake_addr);
	}

	return fake_addr;
}

ADDRINT handleWrite(ADDRINT eip, ADDRINT write_addr,void *fakeWriteH){
	
	//MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
	FakeWriteHandler fakeWrite = *(FakeWriteHandler *)fakeWriteH;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fakeAddr = fakeWrite.getFakeWriteAddress(write_addr);

	if(fakeAddr != write_addr){
		MYINFO("wwwwwwwwwwwwwwww suspicious write from %08x in %s in %08x redirected to %08x", eip, RTN_FindNameByAddress(write_addr).c_str(), write_addr, fakeAddr);
		MYINFO("Binary writes %08x %08x %08x %08x\n" , *(unsigned int *)(fakeAddr) , *(unsigned int *)(fakeAddr+4) , *(unsigned int *)(fakeAddr+8), *(unsigned int *)(fakeAddr+12));
	}
	
	return fakeAddr;
}



//get the first scratch register available
//we build a vector in order to deal with multiple read operand
static REG GetScratchReg(UINT32 index)
{
    static std::vector<REG> regs;

    while (index >= regs.size())
    {
		//get thefirst clean register
        REG reg = PIN_ClaimToolRegister();
        regs.push_back(reg);
    }

    return regs[index];
}


void ToolHider::avoidEvasion(INS ins){

   ADDRINT curEip = INS_Address(ins);
   ProcInfo *pInfo = ProcInfo::getInstance();
   Config *config = Config::getInstance();
   FilterHandler *filterHandler = FilterHandler::getInstance();

	//Filter instructions inside a known library (only graphic dll)
    //  pInfo->isKnownLibraryInstruction(curEip) 
   if(filterHandler->isFilteredLibraryInstruction(curEip)){
		return;
	}

	// 1 - single instruction detection
	if(config->ANTIEVASION_MODE_INS_PATCHING && this->evasionPatcher.patchDispatcher(ins, curEip)){
		//MYINFO("Returned\n");
		return;
	}
	
	if(config->ANTIEVASION_MODE_SREAD){
	// 2 - memory read 
	// Checking if there is a read at addresses that the application shouldn't be aware of
	for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
		if (INS_MemoryOperandIsRead(ins,op)) {
			//if first read initialize the FakeMemoryHandler
			
			if(firstRead == 0){
				fakeMemH.initFakeMemory();
				firstRead=1;
			}
			
			REG scratchReg = GetScratchReg(op);
			
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(handleRead),
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, op,
				IARG_PTR, &fakeMemH,
				IARG_RETURN_REGS, scratchReg,
				IARG_END);
				
			INS_RewriteMemoryOperand(ins, op, scratchReg); 
		}
	  }
	}

	if(config->ANTIEVASION_MODE_SWRITE){
	//3. memory write filter	
	for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
		if(INS_MemoryOperandIsWritten(ins,op) && INS_IsMov(ins)){
			//MYINFO("Cur instruction %s ",INS_Disassemble(ins).c_str());
			REG writeReg = GetScratchReg(op);
			
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(handleWrite),
			IARG_INST_PTR,
			IARG_MEMORYOP_EA, op,
			IARG_PTR, &fakeWriteH,
			IARG_RETURN_REGS, writeReg, // this is an output param
			IARG_END);
				
			INS_RewriteMemoryOperand(ins, op, writeReg); 
			
		}	
	}	
  }
}
