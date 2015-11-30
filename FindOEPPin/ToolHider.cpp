#include "ToolHider.h"


ToolHider::ToolHider(void)
{
}


ToolHider::~ToolHider(void)
{
}




VOID patchint2e(ADDRINT ip, CONTEXT *ctxt ){

	printf("PATCHANDO\n");
	printf("CURRENT ADDR : %08x\n", ip);
	printf("EDX VAL BEFORE : %d\n", PIN_GetContextReg(ctxt,REG_EDX));
	PIN_SetContextReg(ctxt, REG_EDX, 21);
	printf("EDX VAL AFTER : %d\n", PIN_GetContextReg(ctxt,REG_EDX));
	
} 

void ToolHider::avoidEvasion(INS ins){

	static int detected_int2e = 0;
	ADDRINT curEip = INS_Address(ins);
	FilterHandler *filterHandler = FilterHandler::getInstance();

	if(INS_IsMemoryRead(ins)){
		//analyze if this instruction reads a memory region that belong to pinvm.dll / pintool / 
	}

	//pattern match

	string s = INS_Disassemble(ins);
	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(filterHandler->isLibraryInstruction(curEip)){
		return ;
	}

	if(detected_int2e){
			
			MYINFO("Inserting before %08x\n",curEip);
			//W::DebugBreak();
			printf("2) ISTRUZIONE : %s\n", s.c_str());
			//POC
			REGSET regsIn;
			REGSET_AddAll(regsIn);
			REGSET regsOut;
			REGSET_AddAll(regsOut);
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)patchint2e, IARG_INST_PTR, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_END);
			printf("NEXT INSTRUCTION: %s\n" , INS_Disassemble(ins));
			detected_int2e = 0;

	}

	if(s.compare("int 0x2e") == 0){
		printf("FALL THROUGH? %d\n",INS_HasFallThrough(ins));
		//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)patchint2e, IARG_INST_PTR, IARG_END);
		//W::DebugBreak();
		detected_int2e = 1;		
		MYINFO("Found instruction at %08x",curEip);	
		printf("1) ISTRUZIONE : %s\n", s.c_str());
		//INS_Delete(ins);
	}
		
	//timing countermeasures

	//JIT detection
}
