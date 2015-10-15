#pragma once
#include "pin.h"

 

/*
This struct will track the library loaded
at program startup
*/
struct LibraryItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
	string name;
};

class FilterHandler
{
public:
	static FilterHandler* getInstance();
	~FilterHandler(void);
	BOOL isLibraryInstruction(ADDRINT eip);
	BOOL isStackWrite(ADDRINT addr);
	BOOL isTEBWrite(ADDRINT addr);
	VOID setStackBase(ADDRINT addr);
	BOOL isFilteredWrite(ADDRINT addr);
	BOOL isKnownLibrary(const string name);
	VOID addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr);
	VOID showFilteredLibs();


private:
static FilterHandler* instance;
	ADDRINT tebAddr;
	ADDRINT stackBase;
	std::vector<LibraryItem> LibrarySet;
	FilterHandler();
	string libToString(LibraryItem lib);

//	 LibraryHandler(const LibraryHandler&);
//	 LibraryHandler& operator=(const LibraryHandler&);
	
};

