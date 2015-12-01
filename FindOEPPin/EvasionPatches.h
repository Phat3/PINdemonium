#pragma once

#include "pin.h"
#include <map>
#include <string>

class EvasionPatches
{
public:
	EvasionPatches(void);
	~EvasionPatches(void);
	bool patchDispatcher(INS ins,  ADDRINT curEip);

private:
	std::map<string, AFUNPTR> patchesMap;
	AFUNPTR curPatchPointer;
};

