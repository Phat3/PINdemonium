#pragma once
#include "ReportObject.h"
class ReportGeneralInformation : public ReportObject
{

private:
	string name;
	float entropy;


public:
	ReportGeneralInformation();
	ReportGeneralInformation(string name,float initial_entropy);
	string toJson();

};

