#include "ToolHider.h"

static string s;
ToolHider::ToolHider(void)
{
}


ToolHider::~ToolHider(void)
{
}

ADDRINT handleRead (ADDRINT ip, ADDRINT read_addr){
	//MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
	if(!ProcInfo::getInstance()->isAddrInWhiteList(read_addr)){
		MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
		MYINFO("Found suspicious read %08x\n",read_addr);
		string hook = "Cane";
		return (int)&hook;
	}
	//printf("NON HOOK\n");
	return read_addr;
}

void ToolHider::avoidEvasion(INS ins){

	ADDRINT curEip = INS_Address(ins);
	ProcInfo *pInfo = ProcInfo::getInstance();

	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(pInfo->isLibraryInstruction(curEip)){
		return;

	}
	// 1 - single instruction detection
	if(this->evasionPatcher.patchDispatcher(ins, curEip)){
		return;
	}
	
	// 2 - memory fingerprinting
	// Checking if there is a read in the PINVMDll range of addresses. If it is, a pointer to a local string is returned
	for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
		if (INS_MemoryOperandIsRead(ins,op)) {
			
			s = INS_Disassemble(ins);

			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleRead, IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_RETURN_REGS, REG_INST_G0+op, IARG_END);
			INS_RewriteMemoryOperand(ins, op, REG(REG_INST_G0+op));
		}
    }
		
	//timing countermeasures

	//JIT detection
}
