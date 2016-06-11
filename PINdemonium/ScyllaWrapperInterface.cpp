#include "ScyllaWrapperInterface.h"

//singleton
ScyllaWrapperInterface* ScyllaWrapperInterface::instance = 0;

ScyllaWrapperInterface* ScyllaWrapperInterface::getInstance()
{
	
	if (instance == 0)
		instance = new ScyllaWrapperInterface();
	return instance;
}

ScyllaWrapperInterface::ScyllaWrapperInterface(void)
{
}

/**Lauch external tool ScyllaDumper to dump the process with PID pid 
 scylla : string containing the path to the scyllaDumper executable
 pid : pid of the process to dump (Current PID if you want to use the Pin Instrumented Binary)
 curEip : current eip of the program
 outputFile : the name of the dump we want to create
 tmpDump : name of the temp file
 call_plugin_falg : specify if a plugin has to be called if the iat-fix fails
 plugin_full_path : full path to the dll containing the plugin
**/
UINT32 ScyllaWrapperInterface::launchScyllaDumpAndFix(int pid, int curEip, std::string outputFile, std::string tmpDump,  bool call_plugin_flag, std::string plugin_full_path){	
	MYINFO("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
	MYINFO("LAUNCHING SCYLLADUMP AS AN EXTERNAL PROCESS!!");
	MYINFO("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
	MYINFO("CURR EIP  %x",curEip);
	std::string scylla = Config::SCYLLA_DUMPER_PATH;
	W::DWORD exitCode;
	//Creating the string containing the arguments to pass to the ScyllaTest.exe
	std::stringstream scyllaArgsStream;
	scyllaArgsStream << scylla << " ";
	scyllaArgsStream <<  pid << " ";
	scyllaArgsStream << std::hex  << curEip << " ";
	scyllaArgsStream << outputFile << " ";
	scyllaArgsStream << tmpDump << " ";
	scyllaArgsStream << call_plugin_flag << " ";
	scyllaArgsStream << plugin_full_path << " ";
	std::string scyllaArgs = scyllaArgsStream.str();	
	MYINFO("Scylla cmd %s %s",scylla.c_str(),scyllaArgs.c_str());
	//Running external Scyllatest.exe executable
	W::STARTUPINFO si ={0};
	W::PROCESS_INFORMATION pi ={0};
	si.cb=sizeof(si);
	if(!W::CreateProcess(scylla.c_str(),(char *)scyllaArgs.c_str(),NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
		MYERRORE("(INITFUNCTIONCALL)Can't launch Scylla");
		return -5;
	}
	W::GetExitCodeProcess(pi.hProcess, &exitCode);
	W::WaitForSingleObject(pi.hProcess,INFINITE);
	W::CloseHandle(pi.hProcess);
	W::CloseHandle(pi.hThread);

	if(!existFile(outputFile)){
		MYERRORE("Scylla Can't dump the process");
		return exitCode;
	}
	MYINFO("Scylla Finished");
	return SCYLLA_SUCCESS_FIX;
}


//----------------------------------------------------
//THESE METHODS ARE NO LONGER USED!!
//
//Launch dumpAndFix function from as an external process
//----------------------------------------------------
BOOL ScyllaWrapperInterface::existFile (std::string name) {
	if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}

//we have to use loadLibrary and GetProcAddress because PIN doesn't support external libraries
void ScyllaWrapperInterface::loadScyllaLibary(){
	//init
	this->hScyllaWrapper = 0;
	//load library
	this->hScyllaWrapper = W::LoadLibraryEx((W::LPCSTR)Config::SCYLLA_WRAPPER_PATH.c_str(), NULL, NULL);
	W::HANDLE scyh = W::GetModuleHandle((W::LPCSTR)Config::SCYLLA_WRAPPER_PATH.c_str());
	//MYINFO("Address in which scylla is mapped: %08x\n" , scyh);
	//get proc address
	if (this->hScyllaWrapper)
	{
		this->ScyllaDumpAndFix = (def_ScyllaDumpAndFix)W::GetProcAddress((W::HMODULE)this->hScyllaWrapper, "ScyllaDumpAndFix");
		this->ScyllaWrapAddSection = (def_ScyllaWrapAddSection)W::GetProcAddress((W::HMODULE)this->hScyllaWrapper, "ScyllaWrapAddSection");
	}
}

void ScyllaWrapperInterface::unloadScyllaLibrary(){
	W::FreeLibrary((W::HINSTANCE)this->hScyllaWrapper);
}