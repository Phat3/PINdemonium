#pragma once
#include "pin.H"



/*
This struct will track the set of contiguous writes
performed by instructions 
*/
struct WriteItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
	BOOL checked;
};


class WxorXHandler
{
public:
	WxorXHandler(void);
	~WxorXHandler(void);
	BOOL isWriteINS(INS ins);
	VOID handleWrite(INS ins);
	UINT32 getWxorXindex(INS ins);
	BOOL deleteWriteItem(UINT32 writeItemIndex);
private: 
	std::vector<WriteItem> WritesSet;
};

