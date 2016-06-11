#pragma once
#include "pin.H"
#include "Config.h"
#include "ReportGeneralInformation.h"
#include <fstream>

class Report
{
private:
	Report(void);
	static Report *instance;
	ofstream report_file;
	ReportGeneralInformation info;

public:
	static  Report* getInstance();
	void initializeReport(string process_name, float initial_entropy);

};

