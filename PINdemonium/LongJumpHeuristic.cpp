#include "LongJumpHeuristic.h"

//specify the range of the jump when it is considered a long jump or not
const ADDRINT JMP_THRESHOLD =  0x200;

UINT32 LongJumpHeuristic::run(INS ins, ADDRINT prev_ip){
	//filter out the improper values 
	if(prev_ip > 0){
		//get the current IP
		ADDRINT ip = INS_Address(ins);
		//get the difference from the prev_ip and the current ip (the target of the jmp instruction)
		ADDRINT diff = std::abs( (int)ip - (int)prev_ip);
		//if the difference is greater than our threshold then a long jmp i sdetected
		if(diff > JMP_THRESHOLD){
			MYWARN("[LONG JMP DETECTED!!] FROM : %08x	TO : %08x", prev_ip, ip);
			return OEPFINDER_FOUND_OEP
		}
	}
	return OEPFINDER_HEURISTIC_FAIL;

}
