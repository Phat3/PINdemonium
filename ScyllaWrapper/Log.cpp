#include "stdafx.h"
#include <string>

FILE *log_file;

FILE *report_file;

Log* Log::instance = 0;

WCHAR * Log::LOG_FILENAME = L"ScyllaWrapperLog.txt";

//at the first time open the log file
Log::Log(){
	
}

void Log::initLogPath(WCHAR * cur_path){
	
	std::wstring s(cur_path);
	s += std::wstring(Log::LOG_FILENAME);

	const WCHAR *current_log_path = s.c_str();
	this->log_file = _wfopen(current_log_path,L"a");
}

//singleton
Log* Log::getInstance()
{
	if (instance == 0)
		instance = new Log();
	return instance;
}

//flush the buffer and close the file
void Log::closeLogFile()
{
	fflush(this->log_file);
	fclose(this->log_file);
}


//return the file pointer
FILE* Log::getLogFile()
{
	#ifdef LOG_WRITE_TO_FILE
		return this->log_file;
	#else
		return stdout;
	#endif
}


