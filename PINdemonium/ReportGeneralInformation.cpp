#include "ReportGeneralInformation.h"
#include "ReportMainModule.h"

ReportGeneralInformation::ReportGeneralInformation(){
}
ReportGeneralInformation::ReportGeneralInformation(string name, ADDRINT startAddr, ADDRINT endAddr, float initial_entropy)
{
	this->name = name;
	this->entropy = initial_entropy;
	this->main_module = new ReportMainModule(startAddr, endAddr);

}


Json::Value ReportGeneralInformation::toJson(){
	root["name"] = this->name;
	root["entropy"] =this->entropy;
	root["main_module"] = this->main_module->toJson();
	return root;
 
}