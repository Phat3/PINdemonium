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
	
}

void Report::initializeReport(string process_name,float initial_entropy){
	string report_path = Config::getInstance()->getReportPath();
	report_file.open(report_path);

	info = ReportGeneralInformation(process_name,initial_entropy);
	string info_json = info.toJson();
	report_file << "{";
	report_file << "information:";
	report_file << info_json;
	report_file << ",";
	report_file << "dumps:[]";
	report_file << "}";
	report_file.flush();

 }


