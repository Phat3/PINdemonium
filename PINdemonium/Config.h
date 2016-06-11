#pragma once

#include <stdio.h>
#include "WriteInterval.h"
#include "ProcInfo.h"
#include <ctime>
#include <direct.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <fstream>
namespace W {
	#include <windows.h>
}

//if it is uncommented the result will be saved on file otherwise they'll be printed to stdout
#define LOG_WRITE_TO_FILE 1

class Config
{
public:
	static Config* getInstance();
	FILE* Config::getLogFile();
	FILE* Config::getTestFile();
	//getter
	string getBasePath();
	string getCurrentDumpFilePath();
	string getCurrentDetectedListPath();
	string getNotWorkingPath();
	string Config::getWorkingDir();
	long double getDumpNumber();
	
	//utils
	void incrementDumpNumber();
	void Config::closeLogFile();
	void Config::closeReportFile();
	void writeOnReport(ADDRINT ip, WriteInterval wi);
	void Config::writeOnTimeLog(string s);
	void setWorking (int working);
	void setNewWorkingDirectory();

	//files and paths
	static const string PIN_DIRECTORY_PATH_DEP;
	static const string PIN_DIRECTORY_PATH_OUTPUT;
	static const string PINDEMONIUM_PLUGIN_PATH;
	static const string LOG_FILENAME;
	static const string REPORT_FILENAME;
	static const string IDA_PATH;
	static const string IDAP_BAD_IMPORTS_CHECKER;
	static const string BAD_IMPORTS_LIST;
	static const string DETECTED_BAD_IMPORTS_LIST;
	static const string SCYLLA_DUMPER_PATH;
	static const string SCYLLA_WRAPPER_PATH;
	static const string PIN_DIRECTORY_PATH_OUTPUT_NOT_WORKING;
	static const string DUMPER_SELECTOR_PATH;

	//--------------------------Command line Tuning Flags----------------------------
	static const bool  ATTACH_DEBUGGER;
	//Tunable from command line
	bool INTER_WRITESET_ANALYSIS_ENABLE; //Trigger the analysis inside a WriteSet in which WxorX is already broken if a Long JMP is encontered (MPress packer)
	UINT32 WRITEINTERVAL_MAX_NUMBER_JMP;
	//mode of operation
	bool ADVANCED_IAT_FIX;
	bool POLYMORPHIC_CODE_PATCH;
	bool NULLIFY_UNK_IAT_ENTRY;
	string PLUGIN_FULL_PATH;
	bool CALL_PLUGIN_FLAG;

	//--------------------------Command line Tuning Flags----------------------------
	static const string FILTER_WRITES_ENABLES;        //Which write instructions are filtered(possible values: 'stack teb')
	static const UINT32 TIMEOUT_TIMER_SECONDS;
	static const UINT32 TICK_DIVISOR; //this is used in order to lowe the ticks returnedd from GetTickCount and timeGetTime 
	static const UINT32 CC_DIVISOR; // this is used in order to lower the microseconds returned from the QueryPerformanceCounter 
	static const UINT32 KSYSTEM_TIME_DIVISOR; // this is used to lower the LONG lowpart returned from the timeGetTime in the struct _KSYSTEM_TIME inside kuser_shared_data
	static const UINT32 RDTSC_DIVISOR;
	static const UINT32 INTERRUPT_TIME_DIVISOR;
	static const UINT32 SYSTEM_TIME_DIVISOR;
	static const UINT32 MAX_JUMP_INTER_WRITE_SET_ANALYSIS;

private:
	Config::Config();
	static Config* instance;
	FILE *log_file;
	FILE *report_file;
	FILE *test_file;
	string base_path;
	string working_dir;
	string not_working_path;
	string cur_dump_path;        //Path of the final (IAT fixed) Dump
	string cur_list_path;		 //Path of the list of the detected function
	long double dump_number;
	string getCurDateAndTime();
	int numberOfBadImports;
	int calculateNumberOfBadImports();
	int working;
};

