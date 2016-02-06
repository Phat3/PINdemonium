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
const string Config::PIN_DIRECTORY_PATH_OUTPUT_NOT_WORKING = "NotWorking\\";
const string Config::DUMPER_SELECTOR_PATH = Config::PIN_DIRECTORY_PATH_DEP + "dumperSelector.py";


//Tuning Flags
const bool Config::ATTACH_DEBUGGER = false;
const string Config::FILTER_WRITES_ENABLES = "teb stack";
const UINT32 Config::TIMEOUT_TIMER_SECONDS = 120;

// Divisor of the timing 

const UINT32 Config::TICK_DIVISOR = 300;	//this value is based on exait technique (the time returned is equal to the time returned when the program is not instrumented)
const UINT32 Config::CC_DIVISOR = 350;	//this value is based on exait technique (the time returned is equal to the time returned when the program is not instrumented)

const W::ULONG32 Config::LOW_PART_DIVISOR = 10;
//if we divide high_1_part and high_2_part with two different values the timeGetTime() doesn't work
//it doesn't work because high_1_part and high_2_part are used in order to understand if the value read for the low_part
//is consistent ( high_1_part == high_2_part -> low_part consistent ) 
const UINT32 Config::HIGH_PART_DIVISOR = 1; 

//the rdtsc works like this :
//store the least 32 significant bit of the returned value in EAX and the most 32 significant bit in EDX ( value = EDX:EAX )
const UINT32 Config::RDTSC_DIVISOR = 400;

const UINT32 Config::INTERRUPT_TIME_DIVISOR = 1000;
const UINT32 Config::SYSTEM_TIME_DIVISOR = 10;

Config* Config::instance = 0;


//at the first time open the log file
Config::Config(){

	//set the initial dump number
	this->dump_number = 0;
	//build the path for this execution
	this->base_path = PIN_DIRECTORY_PATH_OUTPUT + this->getCurDateAndTime() + "\\";
	//mk the directory
	_mkdir(this->base_path.c_str());
	this->not_working_path = this->base_path + PIN_DIRECTORY_PATH_OUTPUT_NOT_WORKING;
	_mkdir(this->not_working_path.c_str());
	//create the log and report files
	string log_file_path = this->base_path + LOG_FILENAME;
	string report_file_path = this->base_path + REPORT_FILENAME;

	this->log_file = fopen(log_file_path.c_str(),"w");
	this->report_file = fopen(report_file_path.c_str(),"w");

	this->numberOfBadImports = calculateNumberOfBadImports();
	//initialize the path of the ScyllaWrapperLog
	this->working = -1;
	//move the dumper selector in the directory of the current execution
	W::CopyFile(DUMPER_SELECTOR_PATH.c_str(), (this->base_path + "dumperSelector.py").c_str(), FALSE);
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

string Config::getNotWorkingPath(){
	return this->not_working_path + ProcInfo::getInstance()->getProcName() + "_" + std::to_string(this->dump_number) + ".exe";
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
	char * works = "NO";
	if(this->working == 1)
		works = "PROBABLY YES";
	
	fprintf(this->report_file,"{\"dump number\" : \"%d\", \"runnable?\" : \"%s\", \"ip\" : \"%08x\", \"begin\" : \"%08x\", \"end\" : \"%08x\", \"entropy_flag\" : \"%d\", \"longjmp_flag\" : \"%d\", \"jmp_outer_section_flag\" : \"%d\", \"pushad_popad_flag\" : \"%d\", \"detected_functions\" : \"%d/%d\"}\n", (int)this->getDumpNumber(), works, ip, wi.getAddrBegin(), wi.getAddrEnd(), wi.getEntropyFlag(), wi.getLongJmpFlag(), wi.getJmpOuterSectionFlag(), wi.getPushadPopadflag(), wi.getDetectedFunctions(), this->numberOfBadImports);
	fflush(this->report_file);
}


//Sets if the current dump works or not
void Config::setWorking(int working)
{
	this->working = working;
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


