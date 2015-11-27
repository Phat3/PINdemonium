#include "ToolHider.h"


ToolHider::ToolHider(void)
{
}


ToolHider::~ToolHider(void)
{
}

void ToolHider::avoidEvasion(INS ins){

	if(INS_IsMemoryRead(ins)){
		//analyze if this instruction reads a memory region that belong to pinvm.dll / pintool / 
	}

	//pattern match

	//timing countermeasures

	//JIT detection
}
