#include "ReportDump.h"
#include "ReportLongJump.h"

ReportDump::ReportDump(){}

ReportDump::ReportDump(ADDRINT eip,ADDRINT start_addr, ADDRINT end_addr, int dump_number, bool intra_writeset){
	this->eip = eip;
	this->start_address = start_addr;
	this->end_address = end_addr;
	this->intra_writeset = intra_writeset;
	this->number = dump_number;
}


Json::Value ReportDump::toJson(){
	MYINFO("Generating current dump report");
	root["eip"] = eip;
	root["start_address"] = start_address;
	root["end_address"] = end_address;
	root["intra_writeset"] = intra_writeset;
	root["number"] = number;
	root["heuristics"] = Json::Value(Json::arrayValue);

		

	//iterate over the heuristics and append their json content in the "heuristics field" array of the current dump
	for(auto heur = std::begin(this->heuristics); heur != std::end(this->heuristics); ++heur){
		ReportObject * cur_heur = *heur;       
		Json::Value heur_json = cur_heur->toJson();     //generate the json of the heuristic
		root["heuristics"].append(heur_json);			//append the heuristic json to the current dump json 
		delete cur_heur;								// free the heuristic object
	}
	return root;
	
}

void ReportDump::addHeuristic(ReportObject* heur){
	heuristics.push_back(heur);
}
