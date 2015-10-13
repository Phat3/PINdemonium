#pragma once

#include "pin.H"
#include "WxorXHandler.h"
#include "LibraryHandler.h"



#define INLIB -5;
#define NOT_FOUND_OEP -4;
#define EIP_IN_CUR_WITEM -3;
#define EIP_NOT_IN_CUR_WITEM -2;
#define NOT_WXORX_INST -1
#define FOUND_OEP 0;





class OepFinder
{
public:
	OepFinder(void);
	~OepFinder(void);
	UINT32 IsCurrentInOEP(INS ins);
private:
	WxorXHandler wxorxHandler;
	LibraryHandler libHandler;

	BOOL heuristics(INS ins, UINT32 WriteItemIndex);
};

