#include "ToolHider.h"


ToolHider::ToolHider(void)
{
}


ToolHider::~ToolHider(void)
{
}


void ToolHider::avoidEvasion(INS ins){

	ADDRINT curEip = INS_Address(ins);
	FilterHandler *filterHandler = FilterHandler::getInstance();

	// 1 - single instruction detection

	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(filterHandler->isLibraryInstruction(curEip)){
		return;
	}

	if(this->evasionPatcher.patchDispatcher(ins, curEip)){
		return;
	}

	//2 - memory fingerprinting

	if(INS_IsMemoryRead(ins)){
		//analyze if this instruction reads a memory region that belong to pinvm.dll / pintool / 
	}
		
	//timing countermeasures

	//JIT detection
}
