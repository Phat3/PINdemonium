#pragma once

#include "pin.h"
#include <map>
#include <string>
#include "Config.h"
#include <regex>

namespace W{
	#include <Windows.h>
}

class PatternMatchModule
{
public:
	PatternMatchModule(void);
	~PatternMatchModule(void);
	bool patchDispatcher(INS ins,  ADDRINT curEip);

private:
	std::map<string, AFUNPTR> patchesMap;
	AFUNPTR curPatchPointer;
};

