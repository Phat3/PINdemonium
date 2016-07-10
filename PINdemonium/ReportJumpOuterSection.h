#pragma once
#include "ReportObject.h"

class ReportJumpOuterSection : public ReportObject
{
private:
	string name;
	bool result;
	string prev_section;
	string cur_section;
public:
	ReportJumpOuterSection(void);
	ReportJumpOuterSection(bool res, string prev_sec, string cur_sec);
	Json::Value toJson();
};

