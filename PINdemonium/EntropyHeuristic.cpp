#include "EntropyHeuristic.h"

float threshold=0.2f;

UINT32 EntropyHeuristic::run(){
	ProcInfo *proc_info = ProcInfo::getInstance();
	float entropy_value = proc_info->GetEntropy();
	float initial_entropy = proc_info->getInitialEntropy();
	float difference = abs(entropy_value - initial_entropy)/initial_entropy;
	MYINFO("ENTROPY INITIAL IS %f" , initial_entropy);
	MYINFO("CURRENT ENTROPY IS %f" , entropy_value);
	MYINFO("ENTROPY DIFFERERNCE IS %f" , difference);
	if( difference > threshold){
		return OEPFINDER_FOUND_OEP;
	}
	else return OEPFINDER_HEURISTIC_FAIL;
}




