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
BOOL WriteInterval::checkUpdate(ADDRINT start_addr, ADDRINT end_addr){
	//if the address interval ISN'T before or after the current interval then we have to udate the instance
	return !( (start_addr < this->addr_begin && end_addr < this->addr_end) || (start_addr > this->addr_begin && end_addr > this->addr_end) );
}