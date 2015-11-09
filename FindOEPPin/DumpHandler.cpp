#include "DumpHandler.h"



DumpHandler::DumpHandler(void)
{
}


DumpHandler::~DumpHandler(void)
{
}


BOOL DumpHandler::existFile (string name) {
	if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}

/**
 Lauch external tool ScyllaDumper to dump the process with PID pid 
 scylla: string containing the path to the scyllaDumper executable
 pid: pid of the process to dump (Current PID if you want to use the Pin Instrumented Binary)
 curEip: current eip 
 outputFile: path to the dump file 
**/
BOOL DumpHandler::launchScyllaDumpAndFix(string scylla,int pid, int curEip,string outputFile){	


	MYINFO("CURR EIP %x",curEip);
	//Creating the string containing the arguments to pass to the ScyllaTest.exe
	std::stringstream scyllaArgsStream;
	scyllaArgsStream << scylla << " ";
	scyllaArgsStream <<  pid << " ";
	scyllaArgsStream << std::hex  << curEip << " ";
	scyllaArgsStream << outputFile << " ";
	string scyllaArgs = scyllaArgsStream.str();	

	//sprintf(scyllaArgs,"%s %d %x %s",scylla,pid,curEip,outputFile); //argv[0] is the name of the program
	MYINFO("Scylla cmd %s %s",scylla.c_str(),scyllaArgs.c_str());

	//Running external Scyllatest.exe executable
	W::STARTUPINFO si ={0};
	W::PROCESS_INFORMATION pi ={0};

	si.cb=sizeof(si);

	if(!W::CreateProcess(scylla.c_str(),(char *)scyllaArgs.c_str(),NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
		MYERRORE("(INITFUNCTIONCALL)Can't launch Scylla");
		return false;
	}
	W::WaitForSingleObject(pi.hProcess,INFINITE);
	W::CloseHandle(pi.hProcess);
	W::CloseHandle(pi.hThread);
	
	if(!existFile(outputFile)){
		MYERRORE("Scylla Can't dump the process");
		return false;
	}
	MYINFO("Scylla Finished");
	return true;
}