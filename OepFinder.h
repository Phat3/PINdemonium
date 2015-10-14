#pragma once

#include "pin.H"
#include "WxorXHandler.h"
#include "LibraryHandler.h"
#include "Heuristics.h"


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
	Heuristics heuristics;

private:
	LibraryHandler libHandler;

};

