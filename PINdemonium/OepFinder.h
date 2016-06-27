#pragma once

#include "pin.H"
#include "WxorXHandler.h"
#include "Debug.h"
#include "Heuristics.h"
#include "FilterHandler.h"
#include "ProcInfo.h"
#include "Config.h"
namespace W {
	#include <windows.h>
}
#include "GdbDebugger.h"
#include "ScyllaWrapperInterface.h"
#include "TimeTracker.h"
#include <fstream>

//return value for IsCurrentInOEP function
#define OEPFINDER_INS_FILTERED -3;
#define OEPFINDER_HEURISTIC_FAIL -2 
#define OEPFINDER_NOT_WXORX_INST -1;
#define OEPFINDER_FOUND_OEP 0;

class OepFinder
{

public:
	OepFinder(void);
	~OepFinder(void);
	UINT32 IsCurrentInOEP(INS ins);
	BOOL existFile (std::string name);

private:
	//check if the current instruction is a pushad or a popad
	//if so then set the proper flags in ProcInfo
	void handlePopadAndPushad(INS ins);
	BOOL analysis(WriteInterval item, INS ins, ADDRINT prev_ip, ADDRINT curEip, int ResultDumpAndFix);
	UINT32 checkHeapWxorX(WriteInterval item, ADDRINT curEip , int dumpAndFixResult);
	UINT32 saveHeapZones(std::vector<HeapZone> hzs);
	void interWriteSetJMPAnalysis(ADDRINT curEip,ADDRINT prev_ip,INS ins,UINT32 writeItemIndex, WriteInterval item);
	void getCurrentDlls();
	WxorXHandler *wxorxHandler;
	UINT32 DumpAndFixIAT(ADDRINT curEip);
};

