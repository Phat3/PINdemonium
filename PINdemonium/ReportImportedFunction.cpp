#include "ReportImportedFunction.h"


ReportImportedFunction::ReportImportedFunction(string module, string function)
{
	this->module_name = module;
	this->function_name = function;
}


Json::Value ReportImportedFunction::toJson(){
	root["module"] = this->module_name;
	root["function"] = this->function_name;
	return root;
}