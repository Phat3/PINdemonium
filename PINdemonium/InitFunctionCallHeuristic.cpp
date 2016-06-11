#include "InitFunctionCallHeuristic.h"
#include "ScyllaWrapperInterface.h"


#define MAX_PID_LEN_DECIMAL_REP 6 
#define MAX_ADDRESS_SIZE 8
#define IDAPYTHON_LAUNCHER "idaPythonLauncher.bat"

InitFunctionCall::InitFunctionCall(void)
{
}


InitFunctionCall::~InitFunctionCall(void)
{
}


BOOL InitFunctionCall::existFile (std::string name) {
	if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
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

UINT32 InitFunctionCall::run(ADDRINT curEip,WriteInterval* wi){

	string idap_res_file = Config::getInstance()->getCurrentDetectedListPath();
	string  dumpFile = Config::getInstance()->getCurrentDumpFilePath();
	
	if(!existFile(dumpFile)){
		MYERRORE("Dump file hasn't been created");
		return -1;
	}
	
	launchIdaScript(Config::IDA_PATH, Config::IDAP_BAD_IMPORTS_CHECKER, Config::BAD_IMPORTS_LIST, idap_res_file, dumpFile);
	//Read the result of IdaPython script
	FILE *fd = fopen(idap_res_file.c_str(),"r");
	UINT32 file_size = getFileSize(fd);
	char * init_func_detected = (char *)malloc(file_size);
	fread(init_func_detected,file_size,1,fd);
	MYWARN("Found init functions %s\n",init_func_detected);
	free(init_func_detected);
	fclose(fd);
	int numberOfLines = 0;
	string line;
	std::ifstream myfile(idap_res_file.c_str());
	while (getline(myfile, line))
        ++numberOfLines;
	wi->setDetectedFunctions(numberOfLines);
	return 0;
}

BOOL InitFunctionCall::launchIdaScript(string idaw,string idaPythonScript,string idaPythonInput,string idaPythonOutput,string dumpFile){
	string idaScriptLauncher = Config::getInstance()->getBasePath() + IDAPYTHON_LAUNCHER;
	//Running external idaPython script
	W::STARTUPINFO si ={0};
	W::PROCESS_INFORMATION pi ={0};
	si.cb=sizeof(si);
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
	//Timeout 30 sec for the Ida Python script
	W::WaitForSingleObject(pi.hProcess,30000);
	W::CloseHandle(pi.hProcess);
	W::CloseHandle(pi.hThread);
	MYINFO("idaPythonScript Finished");
	return true;
}




