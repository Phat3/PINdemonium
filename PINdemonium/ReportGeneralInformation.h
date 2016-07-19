#pragma once
#include "ReportObject.h"
#include "json.h"


class ReportGeneralInformation : public ReportObject
{

private:
	string name;
	float entropy;
	ReportObject *main_module;

public:
	ReportGeneralInformation();
	ReportGeneralInformation(string name, ADDRINT startAddr, ADDRINT endAddr, float initial_entropy);
	Json::Value ReportGeneralInformation::toJson();

};

