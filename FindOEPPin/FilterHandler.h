#pragma once
#include "pin.h"
#include "Debug.h"
#include <map>
#include <string>       
#include <sstream> 
#include <iostream>
#include "math.h"
#include "Config.h"
#include "ProcInfo.h"

#define MAX_STACK_SIZE 0x5000    //Used to define the memory range of the stack
#define STACK_BASE_PADDING 0x500 //needed because the stack pointer given by pin is not the highest one
#define TEB_SIZE 0xf28			




class FilterHandler
{
public:
	const static UINT32 FILTER_STACK = 0;
	const static UINT32 FILTER_TEB = 1;

	static FilterHandler* getInstance();
	~FilterHandler(void);
	//setter
	VOID setFilters(const string spaceSeparedFilters);
	VOID setStackBase(ADDRINT addr);
	//utils
	BOOL isFilteredWrite(ADDRINT addr, ADDRINT eip);


private:
static FilterHandler* instance;
	ProcInfo *pInfo;
	ADDRINT tebAddr;								//TEB base address
	ADDRINT stackBase;								//Stack base address
	std::map<std::string,int> filterMap;			//Hashmap containing the association between the 
	int filterExecutionFlag;						//flag which keeps track of the enabled filters
	FilterHandler();
	VOID initFilterMap();
	BOOL isLibStackWrite(ADDRINT addr, ADDRINT eip);
	BOOL isLibTEBWrite(ADDRINT addr,ADDRINT eip);
	BOOL binarySearch (int start, int end, ADDRINT value);

};

