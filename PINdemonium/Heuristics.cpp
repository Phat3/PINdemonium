#include "Heuristics.h"


UINT32 Heuristics::longJmpHeuristic(INS ins, ADDRINT prev_ip){
	LongJumpHeuristic heu = LongJumpHeuristic();
	return heu.run(ins, prev_ip);
}

UINT32 Heuristics::entropyHeuristic(){
	EntropyHeuristic heu = EntropyHeuristic();
	return heu.run();
}

UINT32 Heuristics::jmpOuterSectionHeuristic(INS ins, ADDRINT prev_ip){
	JumpOuterSection heu = JumpOuterSection();
	return heu.run(ins, prev_ip);
}


UINT32 Heuristics::pushadPopadHeuristic(){
	PushadPopadheuristic heu = PushadPopadheuristic();
	return heu.run();
}

UINT32 Heuristics::yaraHeuristic(vector<string> dumps_to_analyse){
 	YaraHeuristic heu = YaraHeuristic();
 	return heu.run(dumps_to_analyse);
 
} 