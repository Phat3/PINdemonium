#include "ReportImportedFunction.h"


ReportImportedFunction::ReportImportedFunction(string module, string function)
{
	this->module_name = module;
	this->function_name = function;

}


Json::Value ReportImportedFunction::toJson(){
	root["mod"] = this->module_name;
	root["func"] = this->function_name;
	return root;
}