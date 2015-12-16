#include "ToolHider.h"

static string s;
ToolHider::ToolHider(void)
{
}


ToolHider::~ToolHider(void)
{
}


ADDRINT handleRead (ADDRINT ip, ADDRINT read_addr,void *fakeMemH){
	//MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
	FakeMemoryHandler fakeMem = *(FakeMemoryHandler *)fakeMemH;
	ADDRINT fakeAddr = fakeMem.getFakeMemory(read_addr);
	

	if(fakeAddr != read_addr){
		string  fakeContent= *(string *)fakeAddr;
		MYINFO("Inside handleRead %08x fakeMemRes  containig %02x\n",read_addr,*fakeContent.c_str());
	
		//static 
		
		//const char * hook = fakeMemRes.c_str();
	//	printf("Inside handleRead %08x cane with %08x  containig %02x\n",read_addr,fakeAddr,fakeContentt.c_str());
		return (int)fakeAddr;
		//return fakeMemRes;
		
	}/*
	if(!ProcInfo::getInstance()->isAddrInWhiteList(read_addr)){
		MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
		MYINFO("Found suspicious read %08x\n",read_addr);
		string hook = "Topo";
		return (int)&hook;
	}
	//printf("NON HOOK\n");*/
	return read_addr;
	
	
}
/*

ADDRINT handleRead (ADDRINT ip, ADDRINT read_addr){

	//ADDRINT fakeMemRes = FakeMemoryHandler::getFakeMemory(read_addr);
	
	if( 0x77666f58 == read_addr){
		
		char * hook = "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa";
		printf("Inside handleRead cane with %08x  containig %02x %02x \n",&hook,*(char *)hook,*((char *)hook + 1));
		return (int)hook;
		//return fakeMemRes;
		
	}
	if(!ProcInfo::getInstance()->isAddrInWhiteList(read_addr)){
		MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
		MYINFO("Found suspicious read %08x\n",read_addr);
		string hook = "Topo";
		return (int)&hook;
	}
	//printf("NON HOOK\n");
	return read_addr;
	
}*/

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
			if(firstRead == 0){
				fakeMemH.initFakeMemory();
				firstRead=1;
			}
			s = INS_Disassemble(ins);

			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleRead, IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_PTR,&fakeMemH, IARG_RETURN_REGS, REG_INST_G0+op, IARG_END);
			INS_RewriteMemoryOperand(ins, op, REG(REG_INST_G0+op));
		}
    }
		
	//timing countermeasures

	//JIT detection
}
