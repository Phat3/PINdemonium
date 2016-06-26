#include "Config.h"

//constanth path and variable for our logging system






//Tuning Flags
const bool Config::ATTACH_DEBUGGER = false;
const UINT32 Config::MAX_JUMP_INTER_WRITE_SET_ANALYSIS = 20;


// singleton
Config* Config::instance = 0;

//singleton
Config* Config::getInstance()
{
	if (instance == 0){
		instance = new Config("C:\\pin\\PINdemoniumDependencies\\config.json");
	}
	return instance;
}

//at the first time open the log file
Config::Config(string config_path){

	loadJson(config_path);
	//set the initial dump number
	//W::DebugBreak();
	this->dump_number = 0;
	//build the path for this execution
	this->base_path = results_path + this->getCurDateAndTime() + "\\";
	//mk the directory
	_mkdir(this->base_path.c_str());
	this->not_working_path = this->base_path + not_working_directory;
	_mkdir(this->not_working_path.c_str());
	//create the log and report files
	string log_file_path = this->base_path + log_filename;

	this->log_file = fopen(log_file_path.c_str(),"w");	
	this->working = -1;
	

}

/* ----------------------------- GETTER -----------------------------*/

string Config::getReportPath(){
	return  this->base_path + this->report_filename;
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

string Config::getCurrentReconstructedImportsPath(){
	return this->base_path + "reconstructed_imports.txt";
}


string Config::getYaraResultPath(){	
 	//Creating the output filename string of the current dump (ie finalDump_0.exe or finalDump_1.exe)
 	return  this->base_path + "yaraResults" + "_" + std::to_string(this->dump_number) + ".txt" ;
 }

string Config::getScyllaDumperPath(){
	return  this->dep_scylla_dumper_path;
}
string Config::getScyllaWrapperPath(){
	return this->dep_scylla_wrapper_path;
}

string Config::getScyllaPluginsPath(){
	return this->plugins_path;
}

string Config::getFilteredWrites(){
	return this->filtered_writes;
}



/* ----------------------------- UTILS -----------------------------*/

void Config::loadJson(string config_path){
	Json::Value root;   // will contains the root value after parsing.
    Json::Reader reader;
    std::ifstream config_file(config_path, std::ifstream::binary);
    bool parsingSuccessful = reader.parse( config_file, root, false );
	if ( !parsingSuccessful ){
		printf("Error parsing the json config file: %s",reader.getFormattedErrorMessages().c_str());
		//Can't use LOG since the log path hasn't been loaded yet
	}
	
	results_path = root["results_path"].asString();
	dependecies_path =  root["dependecies_path"].asString();
	plugins_path = root["plugins_path"].asString();
	log_filename = root["log_filename"].asString();
	report_filename = root["report_filename"].asString();
	not_working_directory = root["not_working_directory"].asString();
	filtered_writes =root["filtered_writes"].asString();
	timeout =root["timeout"].asInt();



	dep_scylla_dumper_path = dependecies_path + "Scylla\\ScyllaDumper.exe";
	dep_scylla_wrapper_path = dependecies_path + "Scylla\\ScyllaWrapper.dll";
	//MYINFO("Load Config %s  %s",PIN_DIRECTORY_PATH_OUTPUT.c_str(),PIN_DIRECTORY_PATH_DEP.c_str());
}

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



