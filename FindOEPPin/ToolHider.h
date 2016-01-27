#pragma once

#include "Pin.h"
#include "Debug.h"
#include "Log.h"
#include "FilterHandler.h"
#include "EvasionPatches.h"
#include "FakeMemoryHandler.h"
#include "FakeWriteHandler.h"
#include "FilterHandler.h"

namespace W {
#include <Windows.h>
}



class ToolHider
{
public:
	ToolHider(void);
	~ToolHider(void);
	void avoidEvasion(INS ins);


private:
	EvasionPatches evasionPatcher;
	FakeMemoryHandler fakeMemH;
	FakeWriteHandler fakeWriteH;
	BOOL firstRead;
	void ScanForMappedFiles();

	
};

