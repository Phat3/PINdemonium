#pragma once

#include "pin.H"

class WriteInterval
{

public:

	WriteInterval(ADDRINT addr_begin, ADDRINT addr_end);
	~WriteInterval(void);
	BOOL checkUpdate(ADDRINT start_addr, ADDRINT end_addr);
	BOOL checkInside(ADDRINT ip);	
	VOID update(ADDRINT start_addr, ADDRINT end_addr);
	ADDRINT getAddrBegin();
	ADDRINT getAddrEnd();

private:
	ADDRINT addr_begin;
	ADDRINT addr_end;

};

