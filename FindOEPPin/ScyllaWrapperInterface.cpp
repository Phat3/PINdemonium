#include "ScyllaWrapperInterface.h"

#include "Config.h"


ScyllaWrapperInterface* ScyllaWrapperInterface::instance = 0;

//singleton
ScyllaWrapperInterface* ScyllaWrapperInterface::getInstance()
{
	
	if (instance == 0)
		instance = new ScyllaWrapperInterface();
	return instance;
}

//we have to use loadLibrary and GetProcAddress because PIN doesn't support external libraries
ScyllaWrapperInterface::ScyllaWrapperInterface(void)
{
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

/**Lauch external tool ScyllaDumper to dump the process with PID pid 
 scylla: string containing the path to the scyllaDumper executable
 pid: pid of the process to dump (Current PID if you want to use the Pin Instrumented Binary)
 curEip: curre
**/
UINT32 ScyllaWrapperInterface::launchScyllaDumpAndFix(int pid, int curEip, std::string outputFile){	

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
	std::string scyllaArgs = scyllaArgsStream.str();	

	//sprintf(scyllaArgs,"%s %d %x %s",scylla,pid,curEip,outputFile); //argv[0] is the name of the program
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
	return exitCode;
}

void ScyllaWrapperInterface::loadScyllaLibary(){

	//init
	this->hScyllaWrapper = 0;
	//load library

	this->hScyllaWrapper = W::LoadLibraryEx("C:\\pin\\PinUnpackerDependencies\\Scylla\\ScyllaWrapper.dll", NULL, NULL);

	W::HANDLE scyh = W::GetModuleHandle("C:\\pin\\PinUnpackerDependencies\\Scylla\\ScyllaWrapper.dll");

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