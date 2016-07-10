#include "ReportLongJump.h"


ReportLongJump::ReportLongJump(void)
{
}

ReportLongJump::ReportLongJump(bool res,ADDRINT prev_ip, int len){
	this->name = "LongJumpHeuristic";
	this->result = res;
	this->prev_ip = prev_ip;
	this->length = len;

}


Json::Value ReportLongJump::toJson(){
	root["name"] = name;
	root["result"] = result;
	root["prev_ip"] = prev_ip;
	root["length"] = length;
	return root;
}