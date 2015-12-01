#pragma once

#include "Pin.h"
#include "Debug.h"
#include "Log.h"
#include "FilterHandler.h"
#include "EvasionPatches.h"



class ToolHider
{
public:
	ToolHider(void);
	~ToolHider(void);
	void avoidEvasion(INS ins);

private:
	EvasionPatches evasionPatcher;

};

