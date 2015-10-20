#include "LongJumpHeuristic.h"

#define JMP_THRESHOLD 0x200

UINT32 LongJumpHeuristic::run(INS ins , ADDRINT prev_ip){

	if(prev_ip > 0){

		MYLOG("CHIAMATA EURISTICA 4!!");
		ADDRINT ip = INS_Address(ins);

		ADDRINT diff;

		if(prev_ip > ip){
			diff = prev_ip - ip;
		}
		else{
			diff = ip - prev_ip;
		}
		
		if(diff > JMP_THRESHOLD){
			MYLOG("[LONG JMP DETECTED!!] FROM : %08x	TO : %08x", prev_ip, ip);
			MYLOG("");
			MYLOG("");
			return OEPFINDER_FOUND_OEP
		}
	}

	return OEPFINDER_HEURISTIC_FAIL;

}
