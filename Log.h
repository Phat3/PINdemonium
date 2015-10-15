#pragma once

#include <stdio.h>

class Log
{

public:
	static Log* getInstance();
	void Log::closeLogFile();
	FILE* Log::getLogFile();

private:
	Log::Log();
	static Log* instance;
	FILE *log_file;
};

