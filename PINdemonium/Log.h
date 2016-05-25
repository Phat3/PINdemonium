#pragma once

#include <stdio.h>
#include "WriteInterval.h"
#include <ctime>
#include <direct.h>
#include "ProcInfo.h"
#include <iomanip>
#include <iostream>
#include <sstream>

//#define LOG_WRITE_TO_FILE 1 //if it is uncommented the result will be saved on file otherwise they'll be printed to stdout



class Log
{

public:
	static Log* getInstance();
	
	FILE* Log::getLogFile();
	//getter
	string getBasePath();
	string getCurrentDumpFilePath();
	string getCurrentDetectedListPath();
	//utils
	void incrementDumpNumber();
	void Log::closeLogFile();
	void Log::closeReportFile();
	void writeOnReport(ADDRINT ip, WriteInterval wi);

	static const string PIN_DIRECTORY_PATH_DEP;
	static const string PIN_DIRECTORY_PATH_OUTPUT;
	static const string LOG_FILENAME;
	static const string REPORT_FILENAME;
	static const string IDA_PATH;
	static const string IDAP_BAD_IMPORTS_CHECKER;
	static const string BAD_IMPORTS_LIST;
	static const string DETECTED_BAD_IMPORTS_LIST;
	static const string SCYLLA_DUMPER_PATH;

	//Tuning Flags
	static const bool INTER_WRITESET_ANALYSIS_ENABLE; //Trigger the analysis inside a WriteSet in which WxorX is already broken if a Long JMP is encontered (MPress packer)
	static const string FILTER_WRITES_ENABLES;
private:

	Log::Log();
	static Log* instance;
	FILE *log_file;
	FILE *report_file;
	string base_path;
	string cur_dump_path;        //Path of the final (IAT fixed) Dump
	string cur_list_path;		 //Path of the list of the detected function
	long double dump_number;
	string getCurDateAndTime();
};

