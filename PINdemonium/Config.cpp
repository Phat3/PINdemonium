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
Config::Config(std::string config_path){

	loadJson(config_path);
	//set the initial dump number
	//W::DebugBreak();
	this->dump_number = 0;
	//build the path for this execution
	this->base_path = results_path + this->getCurDateAndTime() + "\\";

	printf("BASE PATH: %s\n" , this->base_path.c_str());

	//mk the directory
	_mkdir(this->base_path.c_str());

	

	this->heap_dir = this->base_path + "\\HEAP";
	_mkdir(this->heap_dir.c_str());

	printf("HEAP DIR: %s\n" , this->heap_dir.c_str());

	this->injection_dir = this->base_path + "\\INJECTIONS";
	_mkdir(this->injection_dir.c_str());
	printf("INJECTION DIR: %s\n" , this->injection_dir.c_str());


	//create the log and report files
	string log_file_path = this->base_path + log_filename;

	printf("LOG FILE PATH: %s\n" , log_file_path.c_str());

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

string Config::getHeapDir(){
	return this->heap_dir;
}

string Config::getInjectionDir(){
	return this->injection_dir;
}

long double Config::getDumpNumber(){
	return this->dump_number;
}

string Config::getNotWorkingDumpPath(){
	return this->not_working_path + ProcInfo::getInstance()->getProcName() + "_" + std::to_string(this->dump_number) + ".exe";
}

string Config::getWorkingDumpPath(){	
	//Creating the output filename string of the current dump (ie finalDump_0.exe or finalDump_1.exe)
	std::string proc_name = ProcInfo::getInstance()->getProcName();

	//_mkdir(this->base_path.c_str());

	this->working_path = this->working_dir + "\\" + proc_name + "_" + std::to_string(this->dump_number) + ".exe" ;
	return this->working_path;
	
	 
}

string Config::getCurrentDumpPath(){

	string fixed_dump = Config::getInstance()->getWorkingDumpPath();          // path to file generated when scylla is able to fix the IAT and reconstruct the PE
	string not_fixed_dump = Config::getInstance()->getNotWorkingDumpPath();   // path to file generated when scylla is NOT able to and reconstruct the PE
	string dump_to_analyse = "";
	
	if(Helper::existFile(fixed_dump)){ // check if a Scylla fixed dump exist
		dump_to_analyse = fixed_dump;  //we return the fixed dump
	}
	else{
		if(Helper::existFile(not_fixed_dump)){ // check if a not fixed dump exist
			dump_to_analyse = not_fixed_dump; // we return the not fixed dump 
		}
		else{
			MYERRORE("Dump file hasn't been created");  //no file created nothig to return
		}
	}
	return dump_to_analyse;

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


void Config::setNewWorkingDirectory(){
	
	std::string prefix = "dump_";
	this->working_dir = this->base_path + prefix + std::to_string(this->getDumpNumber());

	_mkdir(this->working_dir.c_str());

}

string Config::getWorkingDir(){
	return this->working_dir;
}


void Config::setWorking(int working)
{
	this->working = working;

	std::string working_tag =  this->working_dir + "-[working]";
	std::string not_working_tag =  this->working_dir + "-[not working]";
	std::string not_dumped_tag =  this->working_dir + "-[not dumped]";

	if(working == 0){
		rename(this->working_dir.c_str(),working_tag.c_str());
		this->working_dir = working_tag;
	}
	else{
		rename(this->working_dir.c_str(),not_working_tag.c_str());
		this->working_dir = not_working_tag;
	}
}