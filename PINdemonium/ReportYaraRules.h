#pragma once
#include "ReportObject.h"
#include "Debug.h"
#include "Log.h"

class ReportYaraRules : public ReportObject
{
private: 
	string name;
	bool result;
	string output;
public:
	ReportYaraRules(void);
	ReportYaraRules(bool result,string output);
	Json::Value toJson();
	
};

