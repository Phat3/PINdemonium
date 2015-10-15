#pragma once

#include "pin.h"
#include "Debug.h"


/*
This struct will track the library loaded
at program startup
*/
struct LibraryItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
};

class LibraryHandler
{
public:
	LibraryHandler(void);
	~LibraryHandler(void);
	BOOL filterLib(ADDRINT eip);
private:
	std::vector<LibraryItem> LibrarySet;
	
};

