#pragma once

#include "WriteInterval.h"
#include "pin.H"
#include "Debug.h"
#include "Log.h"

class WxorXHandler
{
public:
	//singleton instance
	static WxorXHandler* getInstance();
	//distruptor
	~WxorXHandler(void);
	//check if the current instruction is a write operation
	BOOL isWriteINS(INS ins);
	//manage the write set that contains the WriteInterval written by the program
	VOID writeSetManager(ADDRINT ip, ADDRINT end_addr, UINT32 size);
	//check if the W xor X law is broken
	UINT32 getWxorXindex(ADDRINT ip);
	//delete the analyzed WriteInterval
	VOID deleteWriteItem(UINT32 writeItemIndex);
	//getter for the data structure
	std::vector<WriteInterval> getWritesSet();

private: 
	//set of the write inteval
	 std::vector<WriteInterval> WritesSet;
	 static WxorXHandler* instance;
	 WxorXHandler(){};
};

