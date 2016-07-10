#pragma once
#include "ReportObject.h"
class ReportImportedFunction : public ReportObject
{
private:
	string module_name;
	string function_name;
public:
	ReportImportedFunction(string module, string function);
	Json::Value toJson();

};

