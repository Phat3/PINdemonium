#include "InitFunctionCallHeuristic.h"

#define MAX_PID_LEN_DECIMAL_REP 6 
#define MAX_ADDRESS_SIZE 8

#define IDAPYTHON_LAUNCHER "idaPythonLauncher.bat"



InitFunctionCall::InitFunctionCall(void)
{


}


InitFunctionCall::~InitFunctionCall(void)
{
}


/**
	Get the size of the file passed as fp
**/
UINT32 InitFunctionCall::getFileSize(FILE * fp){
	fseek(fp, 0L, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
return size;
}



UINT32 InitFunctionCall::run(ADDRINT curEip,WriteInterval wi){

	
	//Getting Current process PID and Base Address
	UINT32 pid = W::GetCurrentProcessId();
	MYINFO("Curr PID %d",pid);
	
	string  dumpFile = Log::getInstance()->getCurrentDumpFilePath();
	string idap_res_file = Log::getInstance()->getCurrentDetectedListPath();

	MYINFO("Current output file dump %s",Log::getInstance()->getCurrentDumpFilePath().c_str());


	//W::DebugBreak();
	//Dumping the process memory and try to reconstructing the IAT
	if(!DumpHandler::launchScyllaDumpAndFix(Log::SCYLLA_DUMPER_PATH,pid,curEip,dumpFile)){
		MYERRORE("Scylla execution Failed");
		Log::getInstance()->incrementDumpNumber(); //Incrementing the dump number even if Scylla is not successful
		return 0;
	}

	launchIdaScript(Log::IDA_PATH, Log::IDAP_BAD_IMPORTS_CHECKER, Log::BAD_IMPORTS_LIST, idap_res_file, dumpFile);

	//Read the result of IdaPython script
	
	FILE *fd = fopen(idap_res_file.c_str(),"r");
	UINT32 file_size = getFileSize(fd);
	char * init_func_detected = (char *)malloc(file_size);
	fread(init_func_detected,file_size,1,fd);
	fclose(fd);

	MYWARN("Found init functions %s\n",init_func_detected);
	
	Log::getInstance()->incrementDumpNumber();    //Incrementing the dump number AFTER the launchIdaScript
	return 0;
}




BOOL InitFunctionCall::launchIdaScript(string idaw,string idaPythonScript,string idaPythonInput,string idaPythonOutput,string dumpFile){
	string idaScriptLauncher = Log::getInstance()->getBasePath() + IDAPYTHON_LAUNCHER;

	//Running external idaPython script
	W::STARTUPINFO si ={0};
	W::PROCESS_INFORMATION pi ={0};

	si.cb=sizeof(si);
	// Create a file batch which run the IdaPython script and execute it

	//sprintf(idaScript,"%s -A -S\"%s %s  %s\" %s",idaw,idaPythonScript,idaPythonInput,idaPythonOutput,dumpFile);
	//Creating the string used to launch the idaPython script
	std::stringstream idaScriptStream;
	idaScriptStream << idaw << " -A -S";
	idaScriptStream << "\"" << idaPythonScript << " " << idaPythonInput << " " << idaPythonOutput << "\" ";
	idaScriptStream << dumpFile << " ";
	string idaScript = idaScriptStream.str();	

	FILE *idaLauncherFile = fopen(idaScriptLauncher.c_str(),"w");
	fwrite(idaScript.c_str(),strlen(idaScript.c_str()),1,idaLauncherFile);
	fclose(idaLauncherFile);
	MYINFO("Launching the IdaPython Script %s Containing %s",idaLauncherFile,idaScript.c_str());
	
	if(!W::CreateProcess(idaScriptLauncher.c_str(),NULL,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi)){
		MYERRORE("Can't launch idaPythonScript");
		return false;
	}

	W::WaitForSingleObject(pi.hProcess,INFINITE);
	W::CloseHandle(pi.hProcess);
	W::CloseHandle(pi.hThread);
	MYINFO("idaPythonScript Finished");
	return true;

}




