#include "ToolHider.h"


ToolHider::ToolHider(void)
{
}


ToolHider::~ToolHider(void)
{
}




VOID patchint2e(ADDRINT ip){

	printf("PATCHANDO\n");
	__asm{
		xor edx,edx;
	}
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
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)patchint2e, IARG_INST_PTR, IARG_END);
			printf("NEXT INSTRUCTION: %s\n" , INS_Disassemble(ins));
	
			detected_int2e = 0;
	}

	if(!s.compare("int 0x2e")){
		//W::DebugBreak();
		detected_int2e = 1;
		
		MYINFO("Found instruction at %08x",curEip);
	
	}
		
	//timing countermeasures

	//JIT detection
}
