#pragma once
#include "pin.h"


/*
This struct will track the library loaded
at program startup
*/
struct LibraryItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
};

class FilterHandler
{
public:
	static FilterHandler* getInstance();
	~FilterHandler(void);
	BOOL isKnownLibInstruction(ADDRINT eip);
	BOOL isStackWrite(ADDRINT addr);
	BOOL isTEBWrite(ADDRINT addr);
	VOID setStackBase(ADDRINT addr);
	BOOL isFilteredWrite(ADDRINT addr);

private:
	ADDRINT tebAddr;
	ADDRINT stackBase;
	std::vector<LibraryItem> LibrarySet;
	FilterHandler();
	static FilterHandler* instance;
//	 LibraryHandler(const LibraryHandler&);
//	 LibraryHandler& operator=(const LibraryHandler&);
	
};

