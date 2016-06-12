#pragma once
#include "Heuristics.h"
#include "ReportEntropy.h"


class EntropyHeuristic
{
public:
	UINT32 run();
	float GetEntropy();
};
