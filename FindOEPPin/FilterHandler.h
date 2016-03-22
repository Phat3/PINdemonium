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

	
class FilterHandler
{
public:
	const static UINT32 FILTER_STACK = 0;
	const static UINT32 FILTER_TEB = 1;

	static FilterHandler* getInstance();
	~FilterHandler(void);
	//setter
	VOID setFilters(const string spaceSeparedFilters);
	//utils
	BOOL isFilteredWrite(ADDRINT addr, ADDRINT eip);
	void addToFilteredLibrary(std::string img_name , ADDRINT start_addr , ADDRINT end_addr);
	BOOL IsNameInFilteredArray(std::string img_name);
	BOOL isFilteredLibraryInstruction(ADDRINT eip);

private:
	static FilterHandler* instance;
	ProcInfo *pInfo;
	std::map<std::string,int> filterMap;			//Hashmap containing the association between the 
	int filterExecutionFlag;						//flag which keeps track of the enabled filters
	FilterHandler();
	VOID initFilterMap();
	BOOL isLibStackWrite(ADDRINT addr, ADDRINT eip);
	BOOL isLibTEBWrite(ADDRINT addr,ADDRINT eip);
	BOOL binarySearch (int start, int end, ADDRINT value);
	std::vector<LibraryItem> filtered_libray;
	std::vector<std::string> filtered_library_name;

};

