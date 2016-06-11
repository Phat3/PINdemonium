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
	Json::FastWriter fastWriter;
	Json::Value report;
	Json::Value info_json = info.toJson();
	report["information"] = info_json;
	report["dumps"] = Json::Value(Json::arrayValue);

	report_file << fastWriter.write(report);
	report_file.flush();

 }


