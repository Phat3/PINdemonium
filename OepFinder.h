#pragma once

#include "pin.H"


#define INLIB -4;
#define NOT_FOUND_OEP -3;
#define EIP_IN_CUR_WITEM -2;
#define EIP_NOT_IN_CUR_WITEM -1;
#define FOUND_OEP 0;


/*
This struct will track the set of contiguous writes
performed by instructions 
*/
struct WriteItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
	BOOL checked;
};

/*
This struct will track the library loaded
at program startup
*/
struct LibraryItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
};


class OepFinder
{
public:
	OepFinder(void);
	~OepFinder(void);
	int IsCurrentInOEP(INS ins);
private: 
	BOOL checkWxorX;
	std::vector<WriteItem> WritesSet;
	std::vector<LibraryItem> LibrarySet;
	BOOL filterLib(ADDRINT eip);
	BOOL isWriteINS(INS ins);
	BOOL handleWrite(INS ins);
	int getWxorXindex(INS ins);
	BOOL heuristics(INS ins, int WriteItemIndex);
	BOOL checkEIPInWriteitem(ADDRINT curEip , int wiIndex);
	BOOL OepFinder::deleteWriteItem(int writeItemIndex);
};

