#pragma once

#include <stdio.h>
#include "WriteInterval.h"
#include <ctime>
#include <direct.h>

//#define LOG_WRITE_TO_FILE 1 //if it is uncommented the result will be saved on file otherwise they'll be printed to stdout

class Log
{

public:
	static Log* getInstance();
	void Log::closeLogFile();
	void Log::closeReportFile();
	FILE* Log::getLogFile();
	void writeOnReport(ADDRINT ip, WriteInterval wi);
	string getBasePath();

private:
	Log::Log();
	static Log* instance;
	FILE *log_file;
	FILE *report_file;
	string base_path;
	string getCurDateAndTime();
};

