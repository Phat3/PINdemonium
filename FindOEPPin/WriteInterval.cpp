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

//----------------------- GETTER / SETTER -----------------------

ADDRINT WriteInterval::getAddrBegin(){
	return this->addr_begin;
}

ADDRINT WriteInterval::getAddrEnd(){
	return this->addr_end;
}

UINT32 WriteInterval::getEntropyFlag(){
	return this->entropy_flag;
}

UINT32 WriteInterval::getLongJmpFlag(){
	return this->long_jmp_flag;
}

UINT32 WriteInterval::getJmpOuterSectionFlag(){
	return this->jmp_outer_section_flag;
}

UINT32 WriteInterval::getPushadPopadflag(){
	return this->pushad_popad_flag;
}

void WriteInterval::setEntropyFlag(UINT32 flag){
	this->entropy_flag = flag;
}

void WriteInterval::setLongJmpFlag(UINT32 flag){
	this->long_jmp_flag = flag;
}

void WriteInterval::setJmpOuterSectionFlag(UINT32 flag){
	this->jmp_outer_section_flag = flag;
}

void WriteInterval::setPushadPopadFlag(UINT32 flag){
	this->pushad_popad_flag = flag;
}

//----------------------- PUBLIC METHODS -----------------------

//check if the value of the given address is between addr_begin and addr_end
BOOL WriteInterval::checkUpdate(ADDRINT start_addr, ADDRINT end_addr){
	//if the address interval ISN'T before or after the current interval then we have to udate the instance
	return !( (start_addr < this->addr_begin && end_addr < this->addr_begin) || (start_addr > this->addr_end && end_addr > this->addr_end) );
}

//update the current obj
VOID WriteInterval::update(ADDRINT start_addr, ADDRINT end_addr){
	//if the new write overlaps the WriteInteval at the end then we have to update the end_addr 
	if( (start_addr >= this->addr_begin) && (start_addr <= this->addr_end) && (end_addr > this->addr_end) ){
		this->addr_end = end_addr;
		return;
	}
	//if the new write overlaps the WriteInteval at the begin then we have to update the addr_begin
	if( (start_addr < this->addr_begin) && (end_addr >= this->addr_begin) && (end_addr <= this->addr_end) ){
		this->addr_begin = start_addr;
		return;
	}
	//otherwise we have to do nothing
}

//check if the ip reside inside the WriteInterval
BOOL WriteInterval::checkInside(ADDRINT ip){
	return (ip >= this->addr_begin && ip <= this->addr_end);
}