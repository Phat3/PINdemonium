#pragma once

#include "pin.H"
#include "Debug.h"
#include "Log.h"
#include "OepFinder.h"
#include "LongJumpHeuristic.h"
#include "EntropyHeuristic.h"

//static class where you have to define all the methods that o some kind of heuristic
class Heuristics
{
public:
	static UINT32 longJmpHeuristic(INS ins, ADDRINT prev_ip);
	static UINT32 entropyHeuristic();
};


