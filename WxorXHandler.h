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
	BOOL handleWrite(INS ins);
	int getWxorXindex(INS ins);
	BOOL deleteWriteItem(int writeItemIndex);
private: 
	std::vector<WriteItem> WritesSet;


};

