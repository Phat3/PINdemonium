#include "PINshield.h"
#include <regex>


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
		MYINFO("ip : %08x in %s reading %08x and it has been redirected to : %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr, fake_addr);
	}
	return fake_addr;
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

void PINshield::avoidEvasion(INS ins){
	
	ADDRINT curEip = INS_Address(ins);
	ProcInfo *pInfo = ProcInfo::getInstance();
	Config *config = Config::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();
	//Filter instructions inside a known library (only graphic dll)
	if(filterHandler->isFilteredLibraryInstruction(curEip)){
		return;
	}

	
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
}
