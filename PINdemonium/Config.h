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
#include "json.h"
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
	//getter
	string getBasePath();
	string getCurrentDumpPath();
	string getWorkingDumpPath();
	string getCurrentReconstructedImportsPath();
	string getNotWorkingDumpPath();
	string getYaraResultPath();
	string getReportPath();
	string getScyllaDumperPath();
	string getScyllaWrapperPath();
	string getScyllaPluginsPath();
	long double getDumpNumber();
	string getFilteredWrites();
	
	
	//utils
	void incrementDumpNumber();
	void Config::closeLogFile();
	void Config::writeOnTimeLog(string s);
	void setWorking (int working);
	void setNewWorkingDirectory();
	string getWorkingDir();
	string getHeapDir();
	string getInjectionDir();

	//--------------------------Command line Tuning Flags----------------------------
	static const bool  ATTACH_DEBUGGER;
	static const UINT32 MAX_JUMP_INTER_WRITE_SET_ANALYSIS;
	//Tunable from command line
	bool INTER_WRITESET_ANALYSIS_ENABLE; //Trigger the analysis inside a WriteSet in which WxorX is already broken if a Long JMP is encontered (MPress packer)
	UINT32 WRITEINTERVAL_MAX_NUMBER_JMP;
	//mode of operation
	bool ADVANCED_IAT_FIX;
	bool POLYMORPHIC_CODE_PATCH;
	bool NULLIFY_UNK_IAT_ENTRY;
	string PLUGIN_FULL_PATH;
	bool CALL_PLUGIN_FLAG;


private:
	Config::Config(string config_path);
	static Config* instance;
	FILE *log_file;
	string working_dir;
	string base_path;
	string not_working_path;
	string working_path;        //Path of the final (IAT fixed) Dump
	string cur_list_path;		 //Path of the list of the detected function
	string heap_dir;
	string injection_dir;
	long double dump_number;
	string getCurDateAndTime();
	int numberOfBadImports;
	void loadJson(string path);
	int working;

	//files and paths
	string dependecies_path;
	string results_path;
	string plugins_path; 
	string log_filename;
	string report_filename;
	string dep_scylla_dumper_path;
	string dep_scylla_wrapper_path;
	string not_working_directory;
	//command line tuning flags
	string filtered_writes;        //Which write instructions are filtered(possible values: 'stack teb')
	UINT32 timeout;


};

