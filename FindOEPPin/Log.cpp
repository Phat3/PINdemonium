#include "Log.h"

//constanth path and variable for our logging system
const string Log::PIN_DIRECTORY_PATH_OUTPUT = "C:\\pin\\PinUnpackerResults\\";
const string Log::PIN_DIRECTORY_PATH_DEP = "C:\\pin\\PinUnpackerDependencies\\";
const string Log::LOG_FILENAME = "log_FindOEPPin.txt";
const string Log::REPORT_FILENAME = "report_FindOEPPin.txt";
const string Log::IDA_PATH = "\"C:\\Program Files\\IDA 6.6\\idaw.exe\"";
const string Log::IDAP_BAD_IMPORTS_CHECKER = PIN_DIRECTORY_PATH_DEP + "badImportsChecker.py";
const string Log::BAD_IMPORTS_LIST = PIN_DIRECTORY_PATH_DEP + "badImportsList.txt";
const string Log::DETECTED_BAD_IMPORTS_LIST = "detectedBadImportsList";
const string Log::SCYLLA_DUMPER_PATH = PIN_DIRECTORY_PATH_DEP + "Scylla\\ScyllaDumper.exe";

//Tuning Flags
const bool  Log::INTER_WRITESET_ANALYSIS_ENABLE = true;
const string Log::FILTER_WRITES_ENABLES = "teb stack";


Log* Log::instance = 0;


//at the first time open the log file
Log::Log(){

	//set the initial dump number
	this->dump_number = 0;
	//build the path for this execution
	this->base_path = PIN_DIRECTORY_PATH_OUTPUT + this->getCurDateAndTime() + "\\";
	//mk the directory
	_mkdir(this->base_path.c_str());
	//create the log and report files
	string log_file_path = this->base_path + LOG_FILENAME;
	string report_file_path = this->base_path + REPORT_FILENAME;
	this->log_file = fopen(log_file_path.c_str(),"w");
	this->report_file = fopen(report_file_path.c_str(),"w");

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
	this->cur_dump_path = this->base_path + ProcInfo::getInstance()->getProcName() + "_" + std::to_string(this->dump_number) + ".exe" ;

	return this->cur_dump_path;	
}


string Log::getCurrentDetectedListPath(){	
	//Creating the output filename string of the current dump (ie finalDump_0.exe or finalDump_1.exe)
	this->cur_list_path = this->base_path + this->DETECTED_BAD_IMPORTS_LIST + "_" + std::to_string(this->dump_number) + ".txt" ;

	return this->cur_list_path;	
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
	fprintf(this->report_file,"{\"ip\" : \"%08x\", \"begin\" : \"%08x\", \"end\" : \"%08x\", \"entropy_flag\" : \"%d\", \"longjmp_flag\" : \"%d\", \"jmp_oter_section_flag\" : \"%d\", \"pushad_popad_flag\" : \"%d\"}\n", ip, wi.getAddrBegin(), wi.getAddrEnd(), wi.getEntropyFlag(), wi.getLongJmpFlag(), wi.getJmpOuterSectionFlag(), wi.getPushadPopadflag());
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

//Increment dump number
void Log::incrementDumpNumber(){
	this->dump_number++;
}


