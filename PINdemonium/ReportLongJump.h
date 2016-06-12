#pragma once
#include "ReportObject.h"

class ReportLongJump : public ReportObject
{

private:
	string name;
	bool result;
	ADDRINT prev_ip;
	int length;
public:
	ReportLongJump(void);
	ReportLongJump(bool res,ADDRINT prev_ip, int len);
	Json::Value toJson();
	
};

