#include "ReportGeneralInformation.h"


ReportGeneralInformation::ReportGeneralInformation(){
}
ReportGeneralInformation::ReportGeneralInformation(string name,float initial_entropy)
{
	this->name = name;
	this->entropy = initial_entropy;
}


string ReportGeneralInformation::toJson(){
	return "{name:" +  this->name +  \
			"entropy:" + to_string((long double)this->entropy) + \
			"}";
}