#include "WriteInterval.h"

//set the new WriteInterval object with the begin address and the end address of the current write operation
WriteInterval::WriteInterval(ADDRINT addr_begin, ADDRINT addr_end)
{
	this->addr_begin = addr_begin;
	this->addr_end = addr_end;
}


WriteInterval::~WriteInterval(void)
{
}

//check if the value of the given address is between addr_begin and addr_end
BOOL WriteInterval::checkIfInside(ADDRINT addr){
	return ( (addr >= this->addr_begin) && (addr >= this->addr_begin));
}