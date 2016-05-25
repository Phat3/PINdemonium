#include "PINshield.h"
#include <regex>

#define KUSER_SHARED_DATA_ADDRESS 0x7ffe0000
#define KUSER_SHARED_DATA_SIZE 0x3e0 

PINshield::PINshield(void)
{
}


PINshield::~PINshield(void)
{
}


ADDRINT handleRead(ADDRINT eip, ADDRINT read_addr,void *fake_mem_h){
	FakeReadHandler fake_mem = *(FakeReadHandler *)fake_mem_h;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fake_addr = fake_mem.getFakeMemory(read_addr, eip);
	if(fake_addr == NULL){
		MYINFO("%08x in %s reading %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr);
	}
	if(read_addr == 0){
		return read_addr; // let the program trigger its exception if it want
	}
	if (fake_addr != read_addr){
		if(read_addr < KUSER_SHARED_DATA_ADDRESS  || read_addr > KUSER_SHARED_DATA_ADDRESS + KUSER_SHARED_DATA_SIZE){
			MYTEST("handleRead_evasion %08x read at %08x",eip,read_addr);
		}
		MYINFO("ip : %08x in %s reading %08x and it has been redirected to : %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr, fake_addr);
	}
	return fake_addr;
}

ADDRINT handleWrite(ADDRINT eip, ADDRINT write_addr,void *fakeWriteH){	
	FakeWriteHandler fakeWrite = *(FakeWriteHandler *)fakeWriteH;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fakeAddr = fakeWrite.getFakeWriteAddress(write_addr);
	if(write_addr == 0){
		return write_addr; // let the program trigger its exception if it want
	}
	if(fakeAddr != write_addr){
		MYTEST("handleWrite_evasion %08x",write_addr);
		MYINFO("suspicious write from %08x in %s in %08x redirected to %08x", eip, RTN_FindNameByAddress(write_addr).c_str(), write_addr, fakeAddr);
		MYINFO("Binary writes %08x\n" , *(unsigned int *)(fakeAddr));
	}
	return fakeAddr;
}

//get the first scratch register available
//we build a vector in order to deal with multiple read operand
static REG GetScratchReg(UINT32 index)
{
    static std::vector<REG> regs;
    while (index >= regs.size()){
		//get thefirst clean register
        REG reg = PIN_ClaimToolRegister();
        regs.push_back(reg);
    }
    return regs[index];
}

// In order to avoid obsidium to take the path of the 'or byte ptr [esp+0x1],0x1' 
VOID KillObsidiumDeadPath(CONTEXT *ctxt){
	PIN_SetContextReg(ctxt,REG_EAX,0x7);
}

void PINshield::avoidEvasion(INS ins){
	
	ADDRINT curEip = INS_Address(ins);
	ProcInfo *pInfo = ProcInfo::getInstance();
	Config *config = Config::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();
	//Filter instructions inside a known library (only graphic dll)
	if(filterHandler->isFilteredLibraryInstruction(curEip)){
		return;
	}
	// Pattern matching in order to avoid the dead path of obsidium
	if(strcmp( (INS_Disassemble(ins).c_str() ),"xor eax, dword ptr [edx+ecx*8+0x4]") == 0){
		MYTEST("Obsidium_evasion");
		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)KillObsidiumDeadPath, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
		}
	// 1 - single instruction detection
	if(config->ANTIEVASION_MODE_INS_PATCHING && this->evasionPatcher.patchDispatcher(ins, curEip)){
		return;
	}
	// 2 - memory read 
	// Checking if there is a read at addresses that the application shouldn't be aware of
	if(config->ANTIEVASION_MODE_SREAD){
		for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
			if (INS_MemoryOperandIsRead(ins,op)) {
				//if first read initialize the FakeReadHandler		
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
	//3. memory write filter
	if(config->ANTIEVASION_MODE_SWRITE){	
		for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
			if(INS_MemoryOperandIsWritten(ins,op) && INS_IsMov(ins)){
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
