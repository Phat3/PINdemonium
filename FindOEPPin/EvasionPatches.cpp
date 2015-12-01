#include "EvasionPatches.h"


//avoid the leak of the modified ip by pin
VOID patchint2e(ADDRINT ip, CONTEXT *ctxt, ADDRINT cur_eip ){
	//set the return value of the int2e (stored in edx) as the current ip
	PIN_SetContextReg(ctxt, REG_EDX, cur_eip);	
} 


EvasionPatches::EvasionPatches(void)
{
	//set the initial patch pointer to zero (an invalid address) 
	this->curPatchPointer = 0x0;
	//create the map for our our patches
	//ex : if i find an int 2e instruction we have the functon pointer for the right patch 
	this->patchesMap.insert( std::pair<string,AFUNPTR>("int 0x2e",(AFUNPTR)patchint2e) );
}


EvasionPatches::~EvasionPatches(void)
{
}

//search if we have a patch for the current instruction and if yes insert the patch in the next round
bool EvasionPatches::patchDispatcher(INS ins, ADDRINT curEip){
	//if we have found an instruction that has to be patchet in the previous round then we have a correct function pointer end we can instrument the code
	//
	//we have to use this trick because some instructions, such as int 2e, don't have a fall throug and is not possible to insert an analysis routine with the IPOINT_AFTER attribute
	if(this->curPatchPointer){
		//all the register in the context can be modified
		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		//add the analysis rtoutine (the patch)
		INS_InsertCall(ins, IPOINT_BEFORE, this->curPatchPointer, IARG_INST_PTR, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_ADDRINT, curEip, IARG_END);
		//invalidate the function pointer for the next round
		this->curPatchPointer = 0x0;
		return true;
	}
	//disasseble the instruction
	string s = INS_Disassemble(ins);
	//search if we have a patch foir this instruction
	std::map<string, AFUNPTR>::iterator item = this->patchesMap.find(s);
	if(item != this->patchesMap.end()){
		//if so retrieve the correct function pointer for the analysis routine at the next round
		this->curPatchPointer = this->patchesMap.at(s);
		return true;
	}
	//otherwiae continue the analysis in the class ToolHider
	return false;

}