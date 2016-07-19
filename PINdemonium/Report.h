#pragma once
#include "pin.H"
#include "Config.h"
#include "ReportGeneralInformation.h"
#include "ReportDump.h"
#include <fstream>
#include "json.h"

class Report
{
private:
	Report(void);
	static Report *instance;
	bool already_initialized;					//keep track if the report has already been initialized
	string report_path;							//path of the report file
	ReportObject *info;				//Object containing general info abount the current analysed executable 
	vector<ReportDump> dumps;
	Json::Value report;							//json object representing current report
	void writeJsonToReport(Json::Value report);	


public:
	static  Report* getInstance();
	void initializeReport(string process_name, ADDRINT startAddr, ADDRINT endAddr, float initial_entropy);
	void createReportDump(ADDRINT eip,ADDRINT start_addr, ADDRINT end_addr, int dump_number, bool intra_writeset, int pid);
	ReportDump& getCurrentDump();
	void closeReportDump();
	void closeReport();


};

