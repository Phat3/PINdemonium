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

class LibraryHandler
{
public:
	static LibraryHandler& getInstance()
    {
        static LibraryHandler    instance; // Guaranteed to be destroyed.
                                          // Instantiated on first use.
        return instance;
    }
	~LibraryHandler(void);
	BOOL isKnownLibInstruction(ADDRINT eip);
	BOOL isStackWrite(INS instruction);
private:
	std::vector<LibraryItem> LibrarySet;
	LibraryHandler(){};
//	 LibraryHandler(const LibraryHandler&);
//	 LibraryHandler& operator=(const LibraryHandler&);
	
};

