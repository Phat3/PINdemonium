#include "ReportYaraRules.h"


ReportYaraRules::ReportYaraRules(void)
{
}

ReportYaraRules::ReportYaraRules(bool result, string output){
	this->name = "YaraRulesHeuristic";
	this->result = result;
	this->output = output;
}

Json::Value ReportYaraRules::toJson(){
	root["name"] = name;
	root["result"] = result;
	root["output"] = output;
	return root;
}
