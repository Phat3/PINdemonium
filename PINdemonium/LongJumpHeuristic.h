#pragma once
#include "Heuristics.h"
#include "Report.h"
#include "ReportLongJump.h"


class LongJumpHeuristic
{
public:
	UINT32 run(INS ins , ADDRINT prev_ip);
};
