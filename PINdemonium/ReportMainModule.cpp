#include "ReportMainModule.h"

ReportMainModule::ReportMainModule(ADDRINT startAddr, ADDRINT endAddr)
{
	this->startAddr = startAddr;
	this->endAddr = endAddr;
}


Json::Value ReportMainModule::toJson(){
	root["start_address"] = this->startAddr;
	root["end_address"] = this->endAddr;
	return root;
}