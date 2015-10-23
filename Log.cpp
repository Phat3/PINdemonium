#include "Log.h"

FILE *log_file;

FILE *report_file;

Log* Log::instance = 0;

//at the first time open the log file
Log::Log(){
	this->log_file = fopen("C:\\pin\\TempOEPin\\log_FindOEPPin.txt","w");
	this->report_file = fopen("C:\\pin\\TempOEPin\\report_FindOEPPin.txt","w");
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

//flush the buffer and close the file
void Log::closeReportFile()
{
	fflush(this->report_file);
	fclose(this->report_file);
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

//flush the buffer and close the file
void Log::writeOnReport(ADDRINT ip, WriteInterval wi)
{
	fprintf(this->report_file,"{ip : %08x, begin : %08x, end : %08x; entropy_flag : %d, longjmp_flag : %d, jmp_oter_section_flag : %d, pushad_popad_flag : %d},\n", ip, wi.getAddrBegin(), wi.getAddrEnd(), wi.getEntropyFlag(), wi.getLongJmpFlag(), wi.getJmpOuterSectionFlag(), wi.getPushadPopadflag());
}

