#pragma once
#include "ReportObject.h"
#include "json.h"


class ReportMainModule : public ReportObject
{

private:
	ADDRINT startAddr;
	ADDRINT endAddr;

public:
	ReportMainModule();
	ReportMainModule(ADDRINT startAddr, ADDRINT endAddr);
	Json::Value ReportMainModule::toJson();

};

