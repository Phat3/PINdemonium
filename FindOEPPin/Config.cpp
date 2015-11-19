#include "Config.h"

//constanth path and variable for our logging system
const string Config::PIN_DIRECTORY_PATH_OUTPUT = "C:\\pin\\PinUnpackerResults\\";
const string Config::PIN_DIRECTORY_PATH_DEP = "C:\\pin\\PinUnpackerDependencies\\";
const string Config::LOG_FILENAME = "log_FindOEPPin.txt";
const string Config::REPORT_FILENAME = "report_FindOEPPin.txt";
const string Config::IDA_PATH = "\"C:\\Program Files\\IDA 6.6\\idaw.exe\"";
const string Config::IDAP_BAD_IMPORTS_CHECKER = PIN_DIRECTORY_PATH_DEP + "badImportsChecker.py";
const string Config::BAD_IMPORTS_LIST = PIN_DIRECTORY_PATH_DEP + "badImportsList.txt";
const string Config::DETECTED_BAD_IMPORTS_LIST = "detectedBadImportsList";
const string Config::SCYLLA_DUMPER_PATH = PIN_DIRECTORY_PATH_DEP + "Scylla\\ScyllaDumper.exe";

//Tuning Flags

const bool  Config::INTER_WRITESET_ANALYSIS_ENABLE = true;
const bool  Config::ATTACH_DEBUGGER = false;
const string Config::FILTER_WRITES_ENABLES = "teb stack";
const UINT32 Config::WRITEINTERVAL_MAX_NUMBER_JMP = 2;
const UINT32 Config::TIMEOUT_TIMER_SECONDS = 120;

Config* Config::instance = 0;


//at the first time open the log file
Config::Config(){

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
	this->numberOfBadImports = calculateNumberOfBadImports();

	//initialize the path of the ScyllaWrapperLog


}

//singleton
Config* Config::getInstance()
{
	if (instance == 0)
		instance = new Config();
	return instance;
}

/* ----------------------------- GETTER -----------------------------*/

//flush the buffer and close the file
void Config::closeReportFile()
{
	fflush(this->report_file);
	fclose(this->report_file);
}

string Config::getBasePath(){
	return this->base_path;
}

long double Config::getDumpNumber(){
	return this->dump_number;
}

string Config::getCurrentDumpFilePath(){	
	//Creating the output filename string of the current dump (ie finalDump_0.exe or finalDump_1.exe)
	this->cur_dump_path = this->base_path + ProcInfo::getInstance()->getProcName() + "_" + std::to_string(this->dump_number) + ".exe" ;
	return this->cur_dump_path;	
}


string Config::getCurrentDetectedListPath(){	
	//Creating the output filename string of the current dump (ie finalDump_0.exe or finalDump_1.exe)
	this->cur_list_path = this->base_path + this->DETECTED_BAD_IMPORTS_LIST + "_" + std::to_string(this->dump_number) + ".txt" ;

	return this->cur_list_path;	
}


/* ----------------------------- UTILS -----------------------------*/

//flush the buffer and close the file
void Config::closeLogFile()
{
	fflush(this->log_file);
	fclose(this->log_file);
}

//return the file pointer
FILE* Config::getLogFile()
{
	#ifdef LOG_WRITE_TO_FILE
		return this->log_file;
	#else
		return stdout;
	#endif
}

//write the JSON resulted by the analysis for this write set
void Config::writeOnReport(ADDRINT ip, WriteInterval wi)
{
	fprintf(this->report_file,"{%d)\"ip\" : \"%08x\", \"begin\" : \"%08x\", \"end\" : \"%08x\", \"entropy_flag\" : \"%d\", \"longjmp_flag\" : \"%d\", \"jmp_oter_section_flag\" : \"%d\", \"pushad_popad_flag\" : \"%d\", \"detected_functions\" : \"%d/%d\"}\n",(int)this->getDumpNumber(),  ip, wi.getAddrBegin(), wi.getAddrEnd(), wi.getEntropyFlag(), wi.getLongJmpFlag(), wi.getJmpOuterSectionFlag(), wi.getPushadPopadflag(), wi.getDetectedFunctions(), this->numberOfBadImports);
	fflush(this->report_file);
}

//return the current date and time as a string
string Config::getCurDateAndTime(){
  time_t rawtime;
  struct tm * timeinfo;
  char buffer[80];

  time (&rawtime);
  timeinfo = localtime(&rawtime);

  strftime(buffer,80,"%Y_%m_%d_%I_%M_%S",timeinfo);
  return string(buffer);
}

//Increment dump number
void Config::incrementDumpNumber(){
	this->dump_number++;
}

int Config::calculateNumberOfBadImports(){

	int numberOfLines = 0;
	string line;

	std::ifstream myfile(BAD_IMPORTS_LIST.c_str());
	while (getline(myfile, line))
        ++numberOfLines;
	
	return numberOfLines;	
}


