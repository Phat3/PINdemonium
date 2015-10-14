#pragma once

#include "pin.H";

class WriteInterval
{

public:

	WriteInterval(ADDRINT addr_begin, ADDRINT addr_end);
	~WriteInterval(void);
	BOOL WriteInterval::checkUpdate(ADDRINT start_addr, ADDRINT end_addr);
	VOID update(ADDRINT start_addr, ADDRINT end_addr);

private:
	ADDRINT addr_begin;
	ADDRINT addr_end;

};

