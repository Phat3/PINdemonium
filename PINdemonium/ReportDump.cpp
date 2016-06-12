#include "ReportDump.h"

ReportDump::ReportDump(){}

ReportDump::ReportDump(ADDRINT eip,ADDRINT start_addr, ADDRINT end_addr, int dump_number, bool intra_writeset){
	this->eip = eip;
	this->start_address = start_addr;
	this->end_address = end_addr;
	this->intra_writeset = intra_writeset;
	this->number = dump_number;
}


Json::Value ReportDump::toJson(){

	root["eip"] = eip;
	root["start_address"] = start_address;
	root["end_address"] = end_address;
	root["intra_writeset"] = intra_writeset;
	root["number"] = number;
	return root;
	
}
