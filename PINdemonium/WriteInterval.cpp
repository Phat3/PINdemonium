#include "WriteInterval.h"


//set the new WriteInterval object with the begin address and the end address of the current write operation
WriteInterval::WriteInterval(ADDRINT addr_begin, ADDRINT addr_end, BOOL heap_flag)
{
	this->addr_begin = addr_begin;
	this->addr_end = addr_end;
	this->broken_flag = 0;
	this->cur_number_jmp = 0;
	this->heap_flag = heap_flag;
	this->detectedFunctions = 0;
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

UINT32 WriteInterval::getBrokenFlag(){
	return this->broken_flag;
}

UINT32 WriteInterval::getThreshold(){
	return (this->addr_end - this->addr_begin)/20;
}

UINT32 WriteInterval::getCurrNumberJMP(){
	return this->cur_number_jmp;
}

BOOL WriteInterval::getHeapFlag(){
	return this->heap_flag;
}

UINT32 WriteInterval::getDetectedFunctions(){
	return this->detectedFunctions;
}


void WriteInterval::setBrokenFlag(BOOL flag){
	this->broken_flag = flag;
}

void WriteInterval::incrementCurrNumberJMP(){
	this->cur_number_jmp = this->cur_number_jmp +1 ;
}

void WriteInterval::setDetectedFunctions(UINT32 numberOfFunctions){
	this->detectedFunctions = numberOfFunctions;
}


//----------------------- PUBLIC METHODS -----------------------

//check if the value of the given address is between addr_begin and addr_end
BOOL WriteInterval::checkUpdate(ADDRINT start_addr, ADDRINT end_addr){
	//if the address interval ISN'T before or after the current interval then we have to udate the instance
	return !( (start_addr < this->addr_begin && end_addr < this->addr_begin) || (start_addr > this->addr_end && end_addr > this->addr_end) );
}

//update the current obj
VOID WriteInterval::update(ADDRINT start_addr, ADDRINT end_addr, BOOL heap_flag){
	this->heap_flag = heap_flag;
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
	//if the new write contains the Write interval we have to update the add_begin and addr end
	if( (start_addr < this->addr_begin) && (end_addr > this->addr_begin) ){
		this->addr_begin = start_addr;
		this->addr_end = end_addr;
		return;
	}
}

//check if the ip reside inside the WriteInterval
BOOL WriteInterval::checkInside(ADDRINT ip){
	return (ip >= this->addr_begin && ip <= this->addr_end);
}




 