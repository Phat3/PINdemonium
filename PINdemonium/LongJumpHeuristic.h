#pragma once
#include "Heuristics.h"


class LongJumpHeuristic
{
public:
	UINT32 run(INS ins , ADDRINT prev_ip);
};
