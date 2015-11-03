#pragma once

#include "pin.H"
#include "WxorXHandler.h"
#include "Debug.h"
#include "Heuristics.h"
#include "FilterHandler.h"
#include "ProcInfo.h"
#include "Log.h"
namespace W {
	#include <windows.h>
}

//return value for IsCurrentInOEP function
#define OEPFINDER_INS_FILTERED -3;
#define OEPFINDER_HEURISTIC_FAIL -2;
#define OEPFINDER_NOT_WXORX_INST -1;
#define OEPFINDER_FOUND_OEP 0;

#define TIME_OUT 300 // 5 minutes

class OepFinder
{

public:
	OepFinder(void);
	~OepFinder(void);
	UINT32 IsCurrentInOEP(INS ins);

private:
	//check if the current instruction is a pushad or a popad
	//if so then set the proper flags in ProcInfo
	void handlePopadAndPushad(INS ins);
	BOOL analysis(WriteInterval item, INS ins, ADDRINT prev_ip, ADDRINT curEip);

};

