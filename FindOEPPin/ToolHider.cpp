#include "ToolHider.h"

ToolHider::ToolHider(void)
{

}


ToolHider::~ToolHider(void)
{
}


void ToolHider::avoidEvasion(INS ins){

	ADDRINT curEip = INS_Address(ins);
	ProcInfo *pInfo = ProcInfo::getInstance();

	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(pInfo->isLibraryInstruction(curEip)){
		return;
	}
	else{
			if(INS_IsProcedureCall(ins)){
			char buffer[500];
			sprintf(buffer, "\nA CALL FROM MAIN MODULE: %s\n" , INS_Disassemble(ins).c_str()); 
			Config::getInstance()->writeOnTimeLog(buffer);	
			}
	}
	// 1 - single instruction detection
	if(this->evasionPatcher.patchDispatcher(ins, curEip)){
		return;
	}
	
	// 2 - memory fingerprinting
	if(INS_IsMemoryRead(ins)){
		//analyze if this instruction reads a memory region that belong to pinvm.dll / pintool / 
	}
		

	//JIT detection
}
