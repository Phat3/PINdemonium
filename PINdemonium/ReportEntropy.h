#pragma once
#include "pin.H"
#include "ReportObject.h"

class ReportEntropy : public ReportObject
{

private:
	string name;
	bool result;
	float current_entropy;
	float difference_entropy;

public:
	ReportEntropy(void);
	ReportEntropy( bool result, float cur_entropy, float difference_entropy);
	Json::Value toJson();
};

