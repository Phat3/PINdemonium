#pragma once
#include "pin.h"
#include "Debug.h"
#include <map>
#include <string>       
#include <sstream> 

#define MAX_STACK_SIZE 0x5000    //Used to define the memory range of the stack
#define STACK_BASE_PADDING 0x500 //needed because the stack pointer given by pin is not the highest one
#define TEB_SIZE 0xf28			

 

/*
This struct will track the library loaded
at program startup
*/
struct LibraryItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
	string name;
};
typedef  BOOL(*filterFunc)(ADDRINT addr,ADDRINT eip);
class FilterHandler
{
public:

	static FilterHandler* getInstance();
	~FilterHandler(void);
	VOID setFilters(string commaSeparedFilters);
	VOID setStackBase(ADDRINT addr);
	BOOL isLibraryInstruction(ADDRINT eip);
	BOOL isFilteredWrite(ADDRINT addr);
	BOOL isKnownLibrary(const string name);
	VOID addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr);
	VOID showFilteredLibs();


private:
static FilterHandler* instance;
	ADDRINT tebAddr;								//TEB base address
	ADDRINT stackBase;								//Stack base address
	std::vector<LibraryItem> LibrarySet;			//vector of know library loaded
	std::map<std::string,filterFunc> filterMap;		//Hashmap containing the association between the 
	FilterHandler();
	string libToString(LibraryItem lib);
	BOOL isStackWrite(ADDRINT addr);
	BOOL isTEBWrite(ADDRINT addr);

//	 LibraryHandler(const LibraryHandler&);
//	 LibraryHandler& operator=(const LibraryHandler&);
	
};

