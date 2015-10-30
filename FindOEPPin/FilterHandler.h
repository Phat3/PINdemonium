#pragma once
#include "pin.h"
#include "Debug.h"
#include <map>
#include <string>       
#include <sstream> 
#include <iostream>
#include "math.h"
#include "Log.h"
namespace W {
	#include <Windows.h>
}

#define MAX_STACK_SIZE 0x5000    //Used to define the memory range of the stack
#define STACK_BASE_PADDING 0x500 //needed because the stack pointer given by pin is not the highest one
#define TEB_SIZE 0xf28			


//This struct will track the library loaded
//at program startup
struct LibraryItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
	string name;
};

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
	BOOL isLibraryInstruction(ADDRINT eip);
	BOOL isFilteredWrite(ADDRINT addr, ADDRINT eip);
	BOOL isKnownLibrary(const string name);
	VOID addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr);
	VOID showFilteredLibs();


private:
static FilterHandler* instance;
	ADDRINT tebAddr;								//TEB base address
	ADDRINT stackBase;								//Stack base address
	std::vector<LibraryItem> LibrarySet;			//vector of know library loaded
	std::map<std::string,int> filterMap;			//Hashmap containing the association between the 
	int filterExecutionFlag;						//flag which keeps track of the enabled filters
	FilterHandler();
	VOID initFilterMap();
	string libToString(LibraryItem lib);
	BOOL isLibStackWrite(ADDRINT addr, ADDRINT eip);
	BOOL isLibTEBWrite(ADDRINT addr,ADDRINT eip);
	BOOL binarySearch (int start, int end, ADDRINT value);

};

