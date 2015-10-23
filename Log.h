#pragma once

#include <stdio.h>
#include "WriteInterval.h"



class Log
{

public:
	static Log* getInstance();
	void Log::closeLogFile();
	void Log::closeReportFile();
	FILE* Log::getLogFile();
	void writeOnReport(ADDRINT ip, WriteInterval wi);

private:
	Log::Log();
	static Log* instance;
	FILE *log_file;
	FILE *report_file;
};

