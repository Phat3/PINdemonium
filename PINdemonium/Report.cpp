#include "Report.h"

// singleton
Report* Report::instance = 0;

Report* Report::getInstance()
{
	if (instance == 0)
		instance = new Report();		
	return instance;
}

Report::Report(void)
{
	already_initialized = false;
	
}

void Report::initializeReport(string process_name, ADDRINT startAddr , ADDRINT endAddr, float initial_entropy){
	//already initialized report (avoid problems when called multiple times)
	if(already_initialized == true){
		return;
	}
	report_path = Config::getInstance()->getReportPath();

	//create the general information object and populate it
	info = new ReportGeneralInformation(process_name, startAddr, endAddr, initial_entropy);
	//create the external structure of the json
	Json::Value info_json = info->toJson();
	report["information"] = info_json;
	report["dumps"] = Json::Value(Json::arrayValue);
	writeJsonToReport(report);
	already_initialized = true;

 }

// Create the DumpReport with initial information about the dump
void Report::createReportDump(ADDRINT eip,ADDRINT start_addr, ADDRINT end_addr, int dump_number, bool intra_writeset,int pid){
	ReportDump cur_dump =  ReportDump(eip,start_addr,end_addr,dump_number,intra_writeset,pid);
	dumps.push_back(cur_dump);

}

//return the current dump object
ReportDump& Report::getCurrentDump(){
	return dumps.at(dumps.size()-1);
}

/*
Close the report for the current Dump and write the results on file
*/
void Report::closeReportDump(){
	ReportDump& cur_dump = getCurrentDump();  
	//get current dump and add it to the json structure
						
	Json::Value cur_dump_json = cur_dump.toJson();
	report["dumps"].append(cur_dump_json);				//add it to the json structure
	writeJsonToReport(report);							//write it to file
	
}

void Report::closeReport(){
	delete info;
}


//------------- Helpers ----------------
//create a new file where writes the current report
void Report::writeJsonToReport(Json::Value report ){
	ofstream report_file;
	report_file.open(report_path,std::ofstream::out);
	Json::FastWriter fastWriter;
	report_file << fastWriter.write(report);
	report_file.flush();
	report_file.close();
}