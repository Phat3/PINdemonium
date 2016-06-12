#include "ReportEntropy.h"


ReportEntropy::ReportEntropy(void)
{
}



ReportEntropy::ReportEntropy(bool result, float cur_entropy, float difference_entropy){
	this->name = "EntropyHeuristic";
	this->result = result;
	this->current_entropy = cur_entropy;
	this->difference_entropy = difference_entropy;
}


Json::Value ReportEntropy::toJson(){
	root["name"] = this->name;
	root["result"] = this->result;
	root["current_entropy"] = this->current_entropy;
	root["difference_entropy_percentage"] = this->difference_entropy;
	return root;
}