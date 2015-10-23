#pragma once

#include <stdio.h>
#include "WriteInterval.h"

#define LOG_WRITE_TO_FILE 1 //if set to 1 the result will be saved on file otherwise they'll be printed to stdout

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

