#include "EvasionPatches.h"
#include "Config.h"
#include <regex>


//----------------------------- PATCH FUNCTIONS -----------------------------//

//avoid the leak of the modified ip by pin
VOID patchInt2e(ADDRINT ip, CONTEXT *ctxt, ADDRINT cur_eip ){

	//set the return value of the int2e (stored in edx) as the current ip
	PIN_SetContextReg(ctxt, REG_EDX, cur_eip);	
} 


//avoid the leak of the modified ip by pin
VOID patchFsave(ADDRINT ip, CONTEXT *ctxt, ADDRINT cur_eip ){

	//set the return value of the int2e (stored in edx) as the current ip
	FPSTATE a;
	//get the current fp unit state
	PIN_GetContextFPState(ctxt, &a);
	//set the correct ip and save the state
	a.fxsave_legacy._fpuip = cur_eip;
	PIN_SetContextFPState(ctxt, &a);
} 

//fake the result of an rdtsc operation by dividing it by RDTSC_DIVISOR
VOID patchRtdsc(ADDRINT ip, CONTEXT *ctxt, ADDRINT cur_eip ){
	//get the two original values ()
	UINT32 eax_value = PIN_GetContextReg(ctxt, REG_EAX);
	UINT32 edx_value = PIN_GetContextReg(ctxt, REG_EDX);
	//store the value of edx in a 64 bit data in order to shift this value correctly
	UINT64 tmp_edx = edx_value;
	//we have to compose the proper returned value (EDX:EAX) so let's shift the value of EDX by 32 bit on the left (tmp_edx00..0) and add to this value eax_value (tmp_edxeax_value) and divide the result by a proper divisor
	UINT64 divided_time = ( (tmp_edx << 32) + eax_value ) / Config::RDTSC_DIVISOR;
	//get the right parts 
	UINT32 eax_new_value = divided_time; 
	UINT32 edx_new_value = divided_time >> 32;	
	//MYINFO("Detected a rdtsc, EAX before = %08x , EAX after = %08x , EDX before: %08x , EDX after: %08x\n", eax_value, eax_new_value, edx_value, edx_new_value);
	//set the registerss
	PIN_SetContextReg(ctxt, REG_EAX,eax_new_value);
	PIN_SetContextReg(ctxt, REG_EDX,edx_new_value);
} 

//fake the result of an rdtsc operation by dividing it by RDTSC_DIVISOR
VOID patchOut(ADDRINT ip, CONTEXT *ctxt, ADDRINT cur_eip ){
	MYINFO("OUT DETECTED!!");
} 

//fake the result of an rdtsc operation by dividing it by RDTSC_DIVISOR
VOID patchIn(ADDRINT ip, CONTEXT *ctxt, ADDRINT cur_eip ){
	MYINFO("IN DETECTED!!");
	UINT32 efs_value = PIN_GetContextReg(ctxt, REG_SEG_FS_BASE);
	UINT32 * pointer_to_next_eh = (UINT32*)efs_value;
	UINT32 * pointer_to_routine_eh = (UINT32*)(efs_value + 4);
	int i = 0;
	/*
	MYINFO("EXCEPTON_RECORD NR : %d \tSEG_FS ADDR : %08x  VAL : %08x\t AL SEG_FS + 4 : %08x\t VAL : %08x", i, pointer_to_next_eh, *pointer_to_next_eh, pointer_to_routine_eh, *pointer_to_routine_eh);
	while( *pointer_to_next_eh != 0xffffffff){
		pointer_to_next_eh = (UINT32*)(*pointer_to_next_eh);
		pointer_to_routine_eh = (UINT32*)(0x0012ffc4 + 4);
		i++;
		MYINFO("EXCEPTON_RECORD NR : %d \tSEG_FS ADDR : %08x  VAL : %08x\t AL SEG_FS + 4 : %08x\t VAL : %08x", i, pointer_to_next_eh, *pointer_to_next_eh, pointer_to_routine_eh, *pointer_to_routine_eh);

	}
	*/
	MYINFO("EXCEPTON_RECORD NR : %d \tSEG_FS ADDR : %08x  VAL : %08x\t AL SEG_FS + 4 : %08x\t VAL : %08x", i, pointer_to_next_eh, *pointer_to_next_eh, pointer_to_routine_eh, *pointer_to_routine_eh);
	MYINFO("EXECUTION REDIRECTED TO : %08x",  *pointer_to_routine_eh);
	PIN_SetContextReg(ctxt, REG_EIP, *pointer_to_routine_eh);
	PIN_ExecuteAt(ctxt);

	//PIN_SetContextReg(ctxt, REG_EAX,);
} 

//----------------------------- END PATCH FUNCTIONS -----------------------------//


EvasionPatches::EvasionPatches(void)
{
	//set the initial patch pointer to zero (an invalid address) 
	this->curPatchPointer = 0x0;
	//create the map for our our patches
	//ex : if i find an int 2e instruction we have the functon pointer for the right patch 
	this->patchesMap.insert( std::pair<string,AFUNPTR>("int 0x2e",(AFUNPTR)patchInt2e) );
	this->patchesMap.insert( std::pair<string,AFUNPTR>("fsave",(AFUNPTR)patchFsave) );
	this->patchesMap.insert( std::pair<string,AFUNPTR>("rdtsc ",(AFUNPTR)patchRtdsc) );	
	this->patchesMap.insert( std::pair<string,AFUNPTR>("out",(AFUNPTR)patchOut) );	
	this->patchesMap.insert( std::pair<string,AFUNPTR>("in",(AFUNPTR)patchIn) );	
}


EvasionPatches::~EvasionPatches(void)
{
}

//search if we have a patch for the current instruction and if yes insert the patch in the next round
bool EvasionPatches::patchDispatcher(INS ins, ADDRINT curEip){
	
	//if we have found an instruction that has to be patched in the previous round then we have a correct function pointer end we can instrument the code
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
	std::string disass_instr = INS_Disassemble(ins);

	//if we find an fsave instruction or similar we have to patch it immediately
	std::regex rx("^f(.*)[save|env](.*)");	
	if (std::regex_match(disass_instr.cbegin(), disass_instr.cend(), rx)){
		//all the register in the context can be modified
		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		//add the analysis rtoutine (the patch)
		INS_InsertCall(ins, IPOINT_BEFORE,  this->patchesMap.at("fsave"), IARG_INST_PTR, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_ADDRINT, curEip, IARG_END);
		return true;
	}
	/*
	std::regex rx2("^out(.*)");	
	if (std::regex_match(disass_instr.cbegin(), disass_instr.cend(), rx2)){
		//all the register in the context can be modified
		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		//add the analysis rtoutine (the patch)
		MYINFO("OUT FALL THROUGH %d address %08x", INS_HasFallThrough(ins), INS_Address(ins));
		INS_InsertCall(ins, IPOINT_BEFORE,  this->patchesMap.at("in"), IARG_INST_PTR, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_ADDRINT, curEip, IARG_END);
		return true;
	}
	
	std::regex rx3("in al, 0x74");	
	if (std::regex_match(disass_instr.cbegin(), disass_instr.cend(), rx3)){
		//all the register in the context can be modified
		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		//add the analysis rtoutine (the patch)
		MYINFO("IN FALL THROUGH %d", INS_HasFallThrough(ins));
		INS_InsertCall(ins, IPOINT_BEFORE,  this->patchesMap.at("in"), IARG_INST_PTR, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_ADDRINT, curEip, IARG_END);
		
		return true;
	}
	*/
	//MYINFO("disass_instr is %s\n" , disass_instr.c_str());
	//search if we have a patch foir this instruction
	std::map<string, AFUNPTR>::iterator item = this->patchesMap.find(disass_instr);
	if(item != this->patchesMap.end()){
		//if so retrieve the correct function pointer for the analysis routine at the next round
		this->curPatchPointer = this->patchesMap.at(disass_instr);
		return true;
	}
	
	//otherwiae continue the analysis in the class ToolHider
	return false;

}