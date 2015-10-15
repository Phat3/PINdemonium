#pragma once

#include "pin.H"

class WriteInterval
{

public:
	//create a new WriteInterval 
	WriteInterval(ADDRINT addr_begin, ADDRINT addr_end);
	~WriteInterval(void);
	//check if we have to expand our interval
	BOOL checkUpdate(ADDRINT start_addr, ADDRINT end_addr);
	//check if a given address is inside our interval
	BOOL checkInside(ADDRINT ip);	
	//update our inteval with the new bounds
	VOID update(ADDRINT start_addr, ADDRINT end_addr);
	//getter
	ADDRINT getAddrBegin();
	ADDRINT getAddrEnd();

private:
	ADDRINT addr_begin;
	ADDRINT addr_end;

};

