#include "EntropyHeuristic.h"

float threshold=0.6f;

UINT32 EntropyHeuristic::run(){

	ProcInfo *proc_info = ProcInfo::getInstance();

	float entropy_value = proc_info->GetEntropy();
	float initial_entropy = proc_info->getInitialEntropy();
	float difference = abs(initial_entropy - entropy_value);

	MYLOG("ENTROPY INITIAL IS %f\n" , initial_entropy);
	MYLOG("CURRENT ENTROPY IS %f\n" , entropy_value);


	if( difference > threshold){

		MYLOG("ENTROPY THRESHOLD IS %f\n" , difference);
		return OEPFINDER_FOUND_OEP;
	
	}

	else return OEPFINDER_HEURISTIC_FAIL;
}




