#include "Log.h"

FILE *log_file;

Log* Log::instance = 0;

//at the first time open the log file
Log::Log(){
	this->log_file = fopen("log_FindOEPPin.txt","w");
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
	return this->log_file;
}

