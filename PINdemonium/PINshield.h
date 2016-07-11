#pragma once
#include "Pin.h"
#include "Debug.h"
#include "Log.h"
#include "FilterHandler.h"
#include "PatternMatchModule.h"
#include "FakeReadHandler.h"
#include "FakeWriteHandler.h"
#include "FilterHandler.h"
namespace W {
	#include <Windows.h>
}

class PINshield
{
public:
	PINshield(void);
	~PINshield(void);
	void avoidEvasion(INS ins);

private:
	FakeReadHandler fakeMemH;
	BOOL firstRead;
};

