#pragma once
#include "WriteInterval.h"
#include "pin.H"




class WxorXHandler
{
public:
	static WxorXHandler& getInstance()
    {
        static WxorXHandler    instance; // Guaranteed to be destroyed.
                                          // Instantiated on first use.
        return instance;
    }
	~WxorXHandler(void);
	BOOL isWriteINS(INS ins);
	VOID writeSetManager(ADDRINT ip, ADDRINT end_addr, UINT32 size);
	UINT32 getWxorXindex(INS ins);
	BOOL deleteWriteItem(UINT32 writeItemIndex);
	std::vector<WriteInterval> getWritesSet();
	
private: 
	 std::vector<WriteInterval> WritesSet;
	 WxorXHandler(){};
//	 WxorXHandler(const WxorXHandler&);
//	 WxorXHandler& operator=(const WxorXHandler&);
};

