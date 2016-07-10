#pragma once
#include "pin.H"

class WriteInterval
{

public:
	//create a new WriteInterval 
	WriteInterval(ADDRINT addr_begin, ADDRINT addr_end, BOOL heap_flag);
	~WriteInterval(void);
	//check if we have to expand our interval
	BOOL checkUpdate(ADDRINT start_addr, ADDRINT end_addr);
	//check if a given address is inside our interval
	BOOL checkInside(ADDRINT ip);	
	//update our inteval with the new bounds
	VOID update(ADDRINT start_addr, ADDRINT end_addr, BOOL heap_flag);
	//getter
	ADDRINT getAddrBegin();
	ADDRINT getAddrEnd();
	UINT32 getBrokenFlag();
	UINT32 getThreshold();
	UINT32 getCurrNumberJMP();
	BOOL getHeapFlag();
	UINT32 getDetectedFunctions();
	//setter
	void setBrokenFlag(BOOL flag);
	void incrementCurrNumberJMP();
	void setDetectedFunctions(UINT32 numberOfFunctions);

private:
	ADDRINT addr_begin;
	ADDRINT addr_end;
	BOOL broken_flag;
	UINT32 cur_number_jmp;
	BOOL heap_flag;
	UINT32 detectedFunctions;
};

