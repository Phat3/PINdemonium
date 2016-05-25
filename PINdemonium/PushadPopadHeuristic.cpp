#include "PushadPopadHeuristic.h"


UINT32 PushadPopadheuristic::run(){
	//filter out the improper values 
	ProcInfo *proc_info = ProcInfo::getInstance();
	//if both the flag are valid our heuristic is valid 
	if( proc_info->getPopadFlag() && proc_info->getPushadFlag() ){
			MYWARN("[PUSHAD POPAD DETECTED !!]");
			return OEPFINDER_FOUND_OEP	
	}
	return OEPFINDER_HEURISTIC_FAIL;
}
