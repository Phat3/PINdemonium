#include "ReportJumpOuterSection.h"


ReportJumpOuterSection::ReportJumpOuterSection(void)
{
}

ReportJumpOuterSection::ReportJumpOuterSection( bool res, string prev_sec, string cur_sec){
	this->name = "JumpOuterSectionHeuristic";
	this->result = res;
	this->prev_section = prev_sec;
	this->cur_section = cur_sec;
}


Json::Value ReportJumpOuterSection::toJson(){
	root["name"] = this->name;
	root["result"] = this->result;
	root["prev_section"] = this->prev_section;
	root["current_section"] = this->cur_section;
	return root;
}


