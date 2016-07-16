#include "ReportDump.h"
#include "ReportLongJump.h"

ReportDump::ReportDump(){}

ReportDump::ReportDump(ADDRINT eip,ADDRINT start_addr, ADDRINT end_addr, int dump_number, bool intra_writeset,int pid){
	this->eip = eip;
	this->start_address = start_addr;
	this->end_address = end_addr;
	this->intra_writeset = intra_writeset;
	this->number = dump_number;
	this->reconstructed_imports = 0;
	this->pid = pid;
}


Json::Value ReportDump::toJson(){
	//MYINFO("Generating current dump report");
	root["eip"] = eip;
	root["start_address"] = start_address;
	root["end_address"] = end_address;
	root["intra_writeset"] = intra_writeset;
	root["number"] = number;
	root["reconstructed_imports"] = reconstructed_imports;
	root["pid"] = pid;
	root["heuristics"] = Json::Value(Json::arrayValue);
	root["imports"] = Json::Value(Json::arrayValue);

		

	//iterate over the heuristics andf append their json content in the "heuristics field" array of the current dump
	for(auto heur = std::begin(this->heuristics); heur != std::end(this->heuristics); ++heur){
		ReportObject * cur_heur = *heur;       
		Json::Value heur_json = cur_heur->toJson();     //generate the json of the heuristic
		root["heuristics"].append(heur_json);			//append the heuristic json to the current dump json 
		delete cur_heur;								// free the heuristic object
	}

	//iterate over the imports and append their json content in the "import field" array of the current dump
	for(auto import = std::begin(this->imported_functions); import != std::end(this->imported_functions); ++import){
		ReportObject * current_import = *import;       
		Json::Value heur_json = current_import->toJson();     //generate the json of the import
		root["imports"].append(heur_json);			//append the import json to the current dump json 
		delete current_import;								// free the import object
	}

	return root;
	
}
//add the heuristic object to the current dump report
void ReportDump::addHeuristic(ReportObject* heur){
	heuristics.push_back(heur);
}

void ReportDump::setImportedFunctions(vector<ReportObject *> imports){
	this->imported_functions = imports;
}

void ReportDump::setNumberOfImports(int imports_number){
	this->reconstructed_imports = imports_number;
}


