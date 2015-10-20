#include "Heuristics.h"

UINT32 Heuristics::longJmpHeuristic(INS ins, ADDRINT prev_ip){
	LongJumpHeuristic heu = LongJumpHeuristic();
	return heu.run(ins, prev_ip);
}

UINT32 Heuristics::entropyHeuristic(){
	EntropyHeuristic heu = EntropyHeuristic();
	return heu.run();
}