#pragma once
#include "Heuristics.h"

class JumpOuterSection

{
public:
	UINT32 JumpOuterSection::run(INS ins, ADDRINT prev_ip);

private:
	//get the name of the section where the ip resides
	string getSectionName(ADDRINT ip);
};

