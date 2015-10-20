#include "LongJumpHeuristic.h"

//specify the range of the jump when it is considered a long jump or not
const ADDRINT JMP_THRESHOLD =  0x200;

UINT32 LongJumpHeuristic::run(INS ins, ADDRINT prev_ip){
	//filter out the improper values 
	if(prev_ip > 0){
		//get the current IP
		ADDRINT ip = INS_Address(ins);

		ADDRINT diff;
		//calculate the difference (we have to implement a modulo for the unsigned hex, this is only a placeholder)
		if(prev_ip > ip){
			diff = prev_ip - ip;
		}
		else{
			diff = ip - prev_ip;
		}
		//if the difference from the IP of the jump to the target of the jmp is greater than our threshold then a long jmp i sdetected
		if(diff > JMP_THRESHOLD){
			MYLOG("[LONG JMP DETECTED!!] FROM : %08x	TO : %08x", prev_ip, ip);
			MYLOG("");
			MYLOG("");
			return OEPFINDER_FOUND_OEP
		}
	}

	return OEPFINDER_HEURISTIC_FAIL;

}
