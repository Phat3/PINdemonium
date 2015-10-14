#pragma once
#include "WriteInterval.h"
#include "pin.H"




class WxorXHandler
{
public:

	static WxorXHandler* getInstance();
	~WxorXHandler(void);
	BOOL isWriteINS(INS ins);
	VOID writeSetManager(ADDRINT ip, ADDRINT end_addr, UINT32 size);
	UINT32 WxorXHandler::getWxorXindex(ADDRINT ip);
	BOOL deleteWriteItem(UINT32 writeItemIndex);
	std::vector<WriteInterval> getWritesSet();

private: 
	 std::vector<WriteInterval> WritesSet;
	 WxorXHandler(){};
	 static WxorXHandler* instance;
};

