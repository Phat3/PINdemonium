#pragma once

#include "pin.H"
#include "Debug.h"
#include "Log.h"
#include "OepFinder.h"
#include "LongJumpHeuristic.h"


class Heuristics
{
public:
	static UINT32 longJmpHeuristic(INS ins, ADDRINT prev_ip);
};


