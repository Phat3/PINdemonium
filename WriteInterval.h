#pragma once

#include "pin.H";

class WriteInterval
{

public:

	WriteInterval(ADDRINT addr_begin, ADDRINT addr_end);
	~WriteInterval(void);
	BOOL WriteInterval::checkIfInside(ADDRINT addr);

private:
	ADDRINT addr_begin;
	ADDRINT addr_end;

};

