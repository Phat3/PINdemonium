<<<<<<< HEAD
#pragma once

#include "pin.H"

class WriteInterval
{

public:

	WriteInterval(ADDRINT addr_begin, ADDRINT addr_end);
	~WriteInterval(void);
	BOOL WriteInterval::checkUpdate(ADDRINT start_addr, ADDRINT end_addr);
	VOID update(ADDRINT start_addr, ADDRINT end_addr);
	ADDRINT getAddrBegin();
	ADDRINT getAddrEnd();

private:
	ADDRINT addr_begin;
	ADDRINT addr_end;

};

=======
#pragma once
class WriteInterval
{
public:
	WriteInterval(void);
	~WriteInterval(void);
};

>>>>>>> heuristics
