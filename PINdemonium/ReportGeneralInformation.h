#pragma once
#include "ReportObject.h"
#include "json.h"


class ReportGeneralInformation : public ReportObject
{

private:
	string name;
	float entropy;


public:
	ReportGeneralInformation();
	ReportGeneralInformation(string name,float initial_entropy);
	Json::Value ReportGeneralInformation::toJson();

};

