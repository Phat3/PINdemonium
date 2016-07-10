#pragma once
#include "ReportObject.h"
#include "Debug.h"
#include "Log.h"

class ReportYaraRules : public ReportObject
{
private: 
	string name;
	bool result;
	vector<string> matched_rules;
public:
	ReportYaraRules(void);
	ReportYaraRules(bool result,vector<string> matched_rule);
	Json::Value toJson();
	
};

