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

		MYINFO("xxxxxxxxxxxxxx %08x in %s reading %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr);
	
	}

	//MYINFO("read_addr was %08x\n",read_addr);
	//MYINFO("fakeAddr is %08x\n",fakeAddr);
	return fakeAddr;
}

ADDRINT handleWrite(ADDRINT eip, ADDRINT write_addr,void *fakeWriteH){
	
	//MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
	FakeWriteHandler fakeWrite = *(FakeWriteHandler *)fakeWriteH;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fakeAddr = fakeWrite.getFakeWriteAddress(write_addr);


	if(fakeAddr == NULL){
		MYINFO("wwwwwwwwwwwwwwww %08x in %s reading %08x",eip, RTN_FindNameByAddress(eip).c_str() , write_addr);
	}
	

	//MYINFO("write addr was %08x\n",write_addr);
	//MYINFO("fakeAddr is %08x\n",fakeAddr);
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
   FilterHandler *filterHandler = FilterHandler::getInstance();

	//Filter instructions inside a known library (only graphic dll)
    //  pInfo->isKnownLibraryInstruction(curEip) 
   if(filterHandler->isFilteredLibraryInstruction(curEip)){
		//MYINFO("That's a GDI\n\n");
		//MYINFO("Name of RTN is %s\n" , RTN_FindNameByAddress(curEip).c_str());
	    //MYINFO("Skipping filtered library code\n");
		return;
	}

	MYINFO("[DEBUG] RTN: %s EIP: %08x INS: %s\n", RTN_FindNameByAddress(curEip).c_str(), curEip , INS_Disassemble(ins).c_str());


	// 1 - single instruction detection
	if(this->evasionPatcher.patchDispatcher(ins, curEip)){
		//MYINFO("Returned\n");
		return;
	}
	
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
			//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleRead,IARG_INST_PTR, IARG_MEMORYREAD_EA, op, IARG_PTR,&fakeMemH, IARG_RETURN_REGS, REG_INST_G0+op, IARG_END);
			//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleRead2,IARG_INST_PTR, IARG_CONTEXT, IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_END);
			//MYINFO("INST : %s", INS_Disassemble(ins).c_str());
			//INS_RewriteMemoryOperand(ins, op, REG(REG_INST_G0+op));
			
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(handleRead),
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, op,
				IARG_PTR, &fakeMemH,
				IARG_RETURN_REGS, scratchReg,
				IARG_END);
				
			INS_RewriteMemoryOperand(ins, op, scratchReg); 
		}
    }

	
	//3. memory write filter	
	for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
		if(INS_MemoryOperandIsWritten(ins,op)){
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
