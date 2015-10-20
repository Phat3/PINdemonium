#include "pin.H"
#include "WriteInterval.h"
#include "OepFinder.h"

#define JMP_THRESHOLD 0x200

UINT32 jmpHeuristic(INS ins , WriteInterval wi){

	return OEPFINDER_HEURISTIC_FAIL;

}

/* 
//this is the right functon ---- we have to change the function signature ----
UINT32 longJmpHeuristic(INS ins , ADDRINT prev_ip){
	//if the previous IP is valid (different from zero by convenction)
	if(prev_ip > 0){
		//get the current IP
		ADDRINT ip = INS_Address(ins);

		ADDRINT diff;
		//get the modulo difference (this is not the final solution, we have to implement an absolute function from unsigned hex)
		if(prev_ip > ip){
			diff = prev_ip - ip;
		}
		else{
			diff = ip - prev_ip;
		}
		//if the difference is greater than the fixed threshold a long jmp is detected
		if(diff > JMP_THRESHOLD){
			MYLOG("[LONG JMP DETECTED!!] FROM : %08x	TO : %08x", prev_ip, ip);
			MYLOG("");
			MYLOG("");
			return OEPFINDER_FOUND_OEP
		}
	}

	return OEPFINDER_HEURISTIC_FAIL;

}
*/