#include "Log.h"
#include <iomanip>
#include <iostream>
#include <sstream>

Log* Log::instance = 0;

//at the first time open the log file
Log::Log(){

	//build the path for this execution
	this->base_path = "C:\\pin\\TempOEPin\\" + this->getCurDateAndTime() + "\\";
	//mk the directory
	_mkdir(this->base_path.c_str());
	//create the log and report files
	string log_file_path = this->base_path + "log_FindOEPPin.txt";
	string report_file_path = this->base_path + "report_FindOEPPin.txt";
	this->log_file = fopen(log_file_path.c_str(),"w");
	this->report_file = fopen(report_file_path.c_str(),"w");

	//Initializing dump file path
	this->dump_path = this->base_path +"finalDump";
	printf("----------------------------------------------------dsadump path %s",this->dump_path.c_str());

}

//singleton
Log* Log::getInstance()
{
	if (instance == 0)
		instance = new Log();
	return instance;
}

/* ----------------------------- GETTER -----------------------------*/

//flush the buffer and close the file
void Log::closeReportFile()
{
	fflush(this->report_file);
	fclose(this->report_file);
}

string Log::getBasePath(){
	return this->base_path;
}

string Log::getCurrentDumpFilePath(){	
	//Creating the output filename string of the current dump (ie finalDump_0.exe or finalDump_1.exe)
	this->cur_dump_path = this->dump_path + std::to_string((long double)ProcInfo::getInstance()->getDumpNumber()) + ".exe" ;
	printf("+++++++++++++++++++++++++++++++++++++current path %s",this->cur_dump_path.c_str());


	return this->cur_dump_path;	
}

/* ----------------------------- UTILS -----------------------------*/

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

//write the JSON resulted by the analysis for this write set
void Log::writeOnReport(ADDRINT ip, WriteInterval wi)
{
	fprintf(this->report_file,"{ip : %08x, begin : %08x, end : %08x; entropy_flag : %d, longjmp_flag : %d, jmp_oter_section_flag : %d, pushad_popad_flag : %d},\n", ip, wi.getAddrBegin(), wi.getAddrEnd(), wi.getEntropyFlag(), wi.getLongJmpFlag(), wi.getJmpOuterSectionFlag(), wi.getPushadPopadflag());
}

//return the current date and time as a string
string Log::getCurDateAndTime(){
  time_t rawtime;
  struct tm * timeinfo;
  char buffer[80];

  time (&rawtime);
  timeinfo = localtime(&rawtime);

  strftime(buffer,80,"%d_%m_%Y_%I_%M_%S",timeinfo);
  return string(buffer);
}


