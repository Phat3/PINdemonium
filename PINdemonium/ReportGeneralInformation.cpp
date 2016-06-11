#include "ReportGeneralInformation.h"


ReportGeneralInformation::ReportGeneralInformation(){
}
ReportGeneralInformation::ReportGeneralInformation(string name,float initial_entropy)
{
	this->name = name;
	this->entropy = initial_entropy;
}


Json::Value ReportGeneralInformation::toJson(){
	Json::Value root;
	root["name"] = this->name;
	root["entropy"] =this->entropy;
	return root;
 
}