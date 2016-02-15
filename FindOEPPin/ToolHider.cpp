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

	if(read_addr == 0){
		return read_addr; // let the program trigger its exception if it want
	}

	if(read_addr >= 0x7555657c && read_addr <= 0x75556580){
		printf("Readed the field x kernel32!BasepCurrentTopLevelFilter\n");
		fflush(stdout);
	} 

	if (fake_addr != read_addr){
		MYINFO("ip : %08x in %s reading %08x and it has been redirected to : %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr, fake_addr);
	}

	return fake_addr;
}

ADDRINT handleWrite(ADDRINT eip, ADDRINT write_addr,void *fakeWriteH){
	

	if(write_addr >= 0x7555657c && write_addr <= 0x7555658f){
		printf("Written the field kernel32!BasepCurrentTopLevelFilter\n");
		fflush(stdout);
	} 

	//MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
	FakeWriteHandler fakeWrite = *(FakeWriteHandler *)fakeWriteH;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fakeAddr = fakeWrite.getFakeWriteAddress(write_addr);


	if(write_addr == 0){
		return write_addr; // let the program trigger its exception if it want
	}

	if(fakeAddr != write_addr){
		MYINFO("wwwwwwwwwwwwwwww suspicious write from %08x in %s in %08x redirected to %08x", eip, RTN_FindNameByAddress(write_addr).c_str(), write_addr, fakeAddr);
		MYINFO("Binary writes %08x\n" , *(unsigned int *)(fakeAddr));
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

//Useful during debugging to force the execution of an exception handler in the SEH 
VOID PrintFs(CONTEXT *ctxt){

	unsigned int flags = PIN_GetContextReg(ctxt,REG_EFLAGS);

	MYINFO("******FLAGS BEFORE are %08x\n" , flags);

	MYINFO("******SETTING THE TRAP FLAG\n");

	//flags = flags | 0x100;

	MYINFO("******FLAGS AFTER are %08x\n" , flags);

	unsigned int efs_value = PIN_GetContextReg(ctxt , REG_SEG_FS_BASE);
	MYINFO("efs_value is %08x , address of next SEH is %08x, current SEH is %08x\n" , efs_value , *(unsigned int *)efs_value , *(unsigned int *)(efs_value + 4));

	unsigned int next_record_address = *(unsigned int *)efs_value;

	
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));
	
	/*
	next_record_address = *(unsigned int *)next_record_address;
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));

	
	
	next_record_address = *(unsigned int *)next_record_address;
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));
	/*
	next_record_address = *(unsigned int *)next_record_address;
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));
	*/

	PIN_SetContextReg(ctxt,REG_EIP,*(unsigned int *)(efs_value+4));
	PIN_ExecuteAt(ctxt);
	
}

//Useful during debuggin in order to print the register context 
VOID PrintContext(CONTEXT *ctxt){
	unsigned int esp_value = PIN_GetContextReg(ctxt , REG_ESP);
	unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
	unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);
	unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
	unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
	unsigned int ebp_value = PIN_GetContextReg(ctxt, REG_EBP);
	unsigned int flags = PIN_GetContextReg(ctxt,REG_EFLAGS);

	MYINFO("Context: EAX: %08x\nEBX: %08x\nECX: %08x\nEDX: %08x\n ESP: %08x\n EBP: %08x\n EFLAGS %08x\n" , eax_value , ebx_value,ecx_value,edx_value,esp_value,ebp_value,flags);
}

//TEMP PATCH TO OBSIDIUM 
VOID ZeroEax(CONTEXT *ctxt){

	PIN_SetContextReg(ctxt,REG_EAX,0);
}


void ToolHider::avoidEvasion(INS ins){

   ADDRINT curEip = INS_Address(ins);
   ProcInfo *pInfo = ProcInfo::getInstance();
   Config *config = Config::getInstance();
   FilterHandler *filterHandler = FilterHandler::getInstance();

	//Filter instructions inside a known library (only graphic dll)
   if(filterHandler->isFilteredLibraryInstruction(curEip)){
		return;
	}


	if(pInfo->searchHeapMap(curEip)!=-1){

	if(strcmp( (INS_Disassemble(ins).c_str() ),"and eax, 0x7") == 0){ // SECOND OBSIDIUM TECHNIQUES TMP PATCH 

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)ZeroEax, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
	 }
} // End if HEAP code 

/*
if(strcmp( (INS_Disassemble(ins).c_str() ),"or dword ptr [esp+0x1], 0x1") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		MYINFO("@@@@@@@@@@@@@@@@@@@@@@@@\n");
		printf("Ecco una push OR - POC \n");
		
		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)PrintFs, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		//INS_Delete(ins);
  }
*/

	//----------- MAIN MODULE--------------------
	
	static int entry_point_passed = 0;
			
	if (curEip == 0x0041e000){ // This is the MessageBoxOBS.exe entry point hardcoded 
		entry_point_passed = 1;
	}
		

	if(entry_point_passed == 1){
	if( pInfo->searchHeapMap(curEip)!=-1){
	MYINFO("@heap->		[DEBUG] Thread: %d  RTN: %s EIP: %08x INS: %s\n", W::GetCurrentThreadId(), RTN_FindNameByAddress(curEip).c_str(), curEip , INS_Disassemble(ins).c_str());
	}
	else{
		if(curEip >= 0x00401000 && curEip <= 0x00436000){
			MYINFO("@MainModule->	Thread: %d	[DEBUG]  RTN: %s EIP: %08x INS: %s\n", W::GetCurrentThreadId(), RTN_FindNameByAddress(curEip).c_str(), curEip , INS_Disassemble(ins).c_str());
		}
		else{
			MYINFO("[DEBUG] Thread: %d RTN: %s EIP: %08x INS: %s\n" , W::GetCurrentThreadId(), RTN_FindNameByAddress(curEip).c_str(), curEip , INS_Disassemble(ins).c_str());
		}
	}
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
